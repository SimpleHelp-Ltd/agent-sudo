use crate::{CONTROL, RUNTIME, Result, fail, security as s};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub v: u32,
    pub enabled: bool,
    pub generation: String,
    pub policy: Vec<(String, String)>,
    pub sudo_version: String,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub v: u32,
    pub id: String,
    pub creator: u32,
    pub uid: u32,
    pub gid: u32,
    pub user: String,
    pub host: String,
    pub boot: String,
    pub generation: String,
    pub created: u64,
    pub expires: u64,
    pub deadline: u64,
    pub verifier: String,
}
impl Grant {
    pub fn metadata(&self) -> serde_json::Value {
        serde_json::json!({"id":self.id,"creator_uid":self.creator,"recipient_uid":self.uid,"recipient":self.user,"host":self.host,"created_utc":utc(self.created),"expires_utc":utc(self.expires),"expired":s::boottime().map(|n|n>=self.deadline).unwrap_or(true)})
    }
}
pub fn utc(sec: u64) -> String {
    let t = sec as libc::time_t;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    if unsafe { libc::gmtime_r(&t, tm.as_mut_ptr()) }.is_null() {
        return "invalid-time".into();
    }
    let tm = unsafe { tm.assume_init() };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}
pub fn ensure_dir(path: &str) -> Result<()> {
    match std::fs::create_dir(path) {
        Ok(()) => {
            std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    };
    s::open(path, true, true)?;
    Ok(())
}
pub fn file_rw(path: &str, create: bool) -> Result<File> {
    let p = std::path::Path::new(path);
    let parent = p
        .parent()
        .and_then(|p| p.to_str())
        .ok_or("invalid protected path")?;
    let name = p
        .file_name()
        .and_then(|p| p.to_str())
        .ok_or("invalid protected name")?;
    let d = s::open(parent, true, true)?;
    s::child(
        &d,
        name,
        libc::O_RDWR | if create { libc::O_CREAT } else { 0 },
        0o600,
    )
}
pub struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
pub fn lock() -> Result<Lock> {
    s::open(CONTROL, true, true)?;
    let f = file_rw(&format!("{CONTROL}/lock"), false)?;
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Lock(f));
        }
        if Instant::now() >= end {
            return fail("maintenance busy");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
pub fn try_lock() -> Result<Lock> {
    s::open(CONTROL, true, true)?;
    let f = file_rw(&format!("{CONTROL}/lock"), false)?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return fail("lock busy");
    }
    Ok(Lock(f))
}
pub fn config() -> Result<Config> {
    let c: Config = serde_json::from_slice(&s::read(&format!("{CONTROL}/config"), 131072, true)?)?;
    if c.v != 2 || !c.enabled {
        return fail("installation disabled or invalid");
    }
    Ok(c)
}
pub fn identity(path: &str) -> Result<String> {
    let b = std::fs::read_to_string(path)?;
    let b = b.trim();
    if b.is_empty() || b.len() > 64 || !b.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-') {
        return fail("invalid machine/boot identity");
    }
    Ok(b.into())
}
pub fn gate(actor: &s::Account, op: &str) -> Result<Config> {
    s::installed()?;
    let c = config()?;
    s::open(RUNTIME, true, true)?;
    if matches!(op, "run" | "status" | "revoke" | "revoke-all")
        && !ids()?.iter().any(|id| {
            read_grant(id).is_ok_and(|g| {
                g.uid == actor.uid
                    && g.user == actor.name
                    && live(&g, &c, s::boottime().unwrap_or(u64::MAX)).is_ok()
            })
        })
    {
        return fail("account has no active grant");
    }
    if matches!(
        op,
        "grant" | "admin-list" | "admin-revoke" | "admin-revoke-created"
    ) {
        crate::maintenance::authorize_admin(actor, op)?;
    }
    let current = crate::maintenance::policy_snapshot()?;
    if current != c.policy {
        return fail("sudo policy changed: administrator must revalidate installation");
    }
    Ok(c)
}
pub fn pending(actor: &s::Account) -> Result<Vec<File>> {
    s::open(RUNTIME, true, true)?;
    let mut locks = Vec::new();
    for (prefix, max) in [
        ("slot-global".to_owned(), 32),
        (format!("slot-uid-{}", actor.uid % 128), 4),
    ] {
        let mut found = None;
        for i in 0..max {
            let f = file_rw(&format!("{RUNTIME}/{prefix}-{i}"), true)?;
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                found = Some(f);
                break;
            }
        }
        match found {
            Some(f) => locks.push(f),
            None => return fail("pending helper limit exceeded"),
        }
    }
    Ok(locks)
}
pub fn valid_id(id: &str) -> Result<()> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return fail("invalid grant ID");
    }
    Ok(())
}
pub fn verifier(id: &str, secret: &str) -> String {
    let mut h = Zeroizing::new(String::from("agent-sudo token verifier v1\0"));
    h.push_str(id);
    h.push('\0');
    h.push_str(secret);
    s::hash(h.as_bytes())
}
pub fn token(t: &str) -> Result<(&str, &str)> {
    let parts: Vec<_> = t.split('.').collect();
    if parts.len() != 3 || parts[0] != "v1" {
        return fail("invalid token");
    }
    valid_id(parts[1])?;
    if parts[2].len() != 64
        || !parts[2]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return fail("invalid token");
    }
    Ok((parts[1], parts[2]))
}
fn path(id: &str) -> Result<String> {
    valid_id(id)?;
    Ok(format!("{RUNTIME}/g-{id}"))
}
pub fn read_grant(id: &str) -> Result<Grant> {
    let g: Grant = serde_json::from_slice(&s::read(&path(id)?, 4096, true)?)?;
    if g.v != 1 || g.id != id || g.verifier.len() != 64 {
        return fail("invalid grant record");
    }
    Ok(g)
}
pub fn ids() -> Result<Vec<String>> {
    s::open(RUNTIME, true, true)?;
    let mut v = Vec::new();
    let mut count = 0;
    for e in std::fs::read_dir(RUNTIME)? {
        count += 1;
        if count > 1024 {
            return fail("runtime inventory exceeds bound");
        }
        let n = e?
            .file_name()
            .into_string()
            .map_err(|_| "invalid state name")?;
        if let Some(id) = n.strip_prefix("g-") {
            valid_id(id)?;
            v.push(id.into());
            if v.len() > 128 {
                return fail("grant limit exceeded");
            }
        }
    }
    v.sort();
    Ok(v)
}
pub fn issue(
    c: &Config,
    actor: &s::Account,
    user: &str,
    minutes: u32,
) -> Result<(Grant, Zeroizing<String>)> {
    let a = s::account(user)?;
    if a.uid == 0 {
        return fail("recipient must be non-root");
    }
    if !(1..=1440).contains(&minutes) {
        return fail("minutes must be 1..1440");
    }
    if ids()?.len() >= 128 {
        return fail("grant limit reached; revoke or clean expired records");
    }
    let id = s::random(16)?;
    let secret = Zeroizing::new(s::random(32)?);
    let now = s::walltime();
    let g = Grant {
        v: 1,
        id: id.clone(),
        creator: actor.uid,
        uid: a.uid,
        gid: a.gid,
        user: a.name,
        host: identity("/etc/machine-id")?,
        boot: identity("/proc/sys/kernel/random/boot_id")?,
        generation: c.generation.clone(),
        created: now,
        expires: now + minutes as u64 * 60,
        deadline: s::boottime()? + minutes as u64 * 60 * 1_000_000_000,
        verifier: verifier(&id, &secret),
    };
    let d = s::open(RUNTIME, true, true)?;
    let name = format!("g-{id}");
    let mut f = s::child(
        &d,
        &name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let result = (|| {
        f.write_all(&serde_json::to_vec(&g)?)?;
        f.sync_all()?;
        d.sync_all()?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = s::unlink(&d, &name);
        return Err(e);
    }
    s::audit_recipient("grant", actor.uid, Some(g.uid), &id, None);
    Ok((g, Zeroizing::new(format!("v1.{id}.{}", *secret))))
}
pub fn before_deadline(now: u64, deadline: u64) -> bool {
    now < deadline
}
pub fn live(g: &Grant, c: &Config, now: u64) -> Result<()> {
    if g.generation != c.generation
        || g.boot != identity("/proc/sys/kernel/random/boot_id")?
        || g.host != identity("/etc/machine-id")?
        || !before_deadline(now, g.deadline)
    {
        return fail("grant expired or invalidated");
    }
    let a = s::account(&g.user)?;
    if a.uid != g.uid || a.gid != g.gid {
        return fail("recipient identity changed");
    }
    Ok(())
}
pub fn admit(c: &Config, actor: &s::Account, t: &str, exe: &str) -> Result<String> {
    let (id, secret) = token(t)?;
    let g = read_grant(id)?;
    if g.uid != actor.uid || g.user != actor.name {
        return fail("grant belongs to another account");
    }
    let v = Zeroizing::new(verifier(id, secret));
    if !bool::from(v.as_bytes().ct_eq(g.verifier.as_bytes())) {
        return fail("invalid token");
    }
    live(&g, c, s::boottime()?)?;
    s::audit_recipient("admit", actor.uid, Some(g.uid), id, Some(exe));
    Ok(id.into())
}
pub fn revoke(id: &str, actor: &s::Account, admin: bool) -> Result<()> {
    let p = path(id)?;
    let g = match read_grant(id) {
        Ok(g) => g,
        Err(e) => {
            if std::fs::symlink_metadata(&p)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            {
                return Ok(());
            }
            return Err(e);
        }
    };
    if !admin && (g.uid != actor.uid || g.user != actor.name) {
        return fail("cannot revoke another account's grant");
    }
    let d = s::open(RUNTIME, true, true)?;
    s::unlink(&d, &format!("g-{id}"))?;
    s::audit_recipient("revoke", actor.uid, Some(g.uid), id, None);
    Ok(())
}
pub fn invalidate() -> Result<()> {
    if std::fs::symlink_metadata(RUNTIME).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(());
    }
    for id in ids()? {
        let p = path(&id)?;
        s::open(&p, false, true)?;
        let d = s::open(RUNTIME, true, true)?;
        s::unlink(&d, &format!("g-{id}"))?;
    }
    s::open(RUNTIME, true, true)?.sync_all()?;
    Ok(())
}
pub fn denial(actor: u32) {
    let result = (|| -> Result<()> {
        let _l = try_lock()?;
        let p = format!("{RUNTIME}/denials");
        let mut f = file_rw(&p, true)?;
        let mut b = String::new();
        (&mut f).take(128).read_to_string(&mut b)?;
        let parts: Vec<_> = b.split_whitespace().collect();
        let minute = s::boottime()? / 60_000_000_000;
        let count = if parts.first().and_then(|x| x.parse::<u64>().ok()) == Some(minute) {
            parts
                .get(1)
                .and_then(|x| x.parse::<u32>().ok())
                .unwrap_or(10)
        } else {
            0
        };
        if count < 10 {
            use std::io::{Seek, SeekFrom};
            f.set_len(0)?;
            f.seek(SeekFrom::Start(0))?;
            write!(f, "{minute} {}", count + 1)?;
            s::audit("denied", actor, "-", None);
        }
        Ok(())
    })();
    let _ = result;
}

/// Drop obsolete per-account admission slots during maintenance. Global slots remain
/// stable; stale helpers still consume a global slot and cannot pass generation checks.
pub fn prune_slots() -> Result<()> {
    for e in std::fs::read_dir(RUNTIME)? {
        let p = e?.path();
        let n = p
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("invalid runtime name")?;
        if let Some(rest) = n.strip_prefix("slot-uid-") {
            let (uid, index) = rest.rsplit_once('-').ok_or("invalid slot name")?;
            let uid: u32 = uid.parse()?;
            let index: u32 = index.parse()?;
            if index >= 4 {
                return fail("invalid slot index");
            }
            if uid != 0 {
                s::open(p.to_str().ok_or("runtime path")?, false, true)?;
                std::fs::remove_file(p)?;
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokens() {
        assert!(token("v1...x").is_err());
        let id = "a".repeat(32);
        let s = "b".repeat(64);
        let t = format!("v1.{id}.{s}");
        assert_eq!(token(&t).unwrap(), (&*id, &*s));
        assert_ne!(verifier(&id, &s), verifier(&id, &"c".repeat(64)));
    }
    #[test]
    fn exact_deadline() {
        assert!(before_deadline(99, 100));
        assert!(!before_deadline(100, 100));
        assert!(!before_deadline(101, 100));
    }
    #[test]
    fn utc_date() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
    }
}
