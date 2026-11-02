use crate::{Result, fail};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path},
};
pub fn harden() -> Result<()> {
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &lim) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        libc::umask(0o077);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    Ok(())
}
pub fn valid_user(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 32
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        || s.starts_with('-')
    {
        return fail("unsupported account name");
    }
    Ok(())
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
}
pub fn account(name: &str) -> Result<Account> {
    valid_user(name)?;
    let c = CString::new(name)?;
    let mut p = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut ptr = std::ptr::null_mut();
    let mut b = vec![0u8; 65536];
    let n = unsafe {
        libc::getpwnam_r(
            c.as_ptr(),
            p.as_mut_ptr(),
            b.as_mut_ptr().cast(),
            b.len(),
            &mut ptr,
        )
    };
    if n != 0 || ptr.is_null() {
        return fail("account not found");
    }
    let p = unsafe { p.assume_init() };
    let result = Account {
        uid: p.pw_uid,
        gid: p.pw_gid,
        name: unsafe { CStr::from_ptr(p.pw_name) }.to_str()?.to_owned(),
    };
    if result.name != name {
        return fail("account identity mismatch");
    }
    Ok(result)
}
pub fn actor() -> Result<Account> {
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getuid() } != 0 {
        return fail("helper requires real and effective root");
    }
    match (
        std::env::var("SUDO_USER"),
        std::env::var("SUDO_UID"),
        std::env::var("SUDO_GID"),
    ) {
        (Ok(n), Ok(u), Ok(g)) => {
            let a = account(&n)?;
            if a.uid != u.parse::<u32>()? || a.gid != g.parse::<u32>()? {
                return fail("inconsistent sudo identity");
            }
            Ok(a)
        }
        (Err(_), Err(_), Err(_)) => account("root"),
        _ => fail("incomplete sudo identity"),
    }
}
pub fn hex(bytes: &[u8]) -> String {
    const H: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}
pub fn random(n: usize) -> Result<String> {
    let mut b = zeroize::Zeroizing::new(vec![0; n]);
    getrandom::fill(&mut b).map_err(|_| "OS randomness failed")?;
    Ok(hex(&b))
}
pub fn hash(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}
pub fn boottime() -> Result<u64> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64)
}
pub fn walltime() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn no_acl(f: &File) -> Result<()> {
    for name in [c"system.posix_acl_access", c"system.posix_acl_default"] {
        let n = unsafe { libc::fgetxattr(f.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if n >= 0 {
            return fail("extended ACL is unsupported");
        }
        let e = std::io::Error::last_os_error().raw_os_error();
        if !matches!(e, Some(libc::ENODATA) | Some(libc::ENOTSUP)) {
            return fail("cannot inspect ACL");
        }
    }
    Ok(())
}
pub fn check(f: &File, dir: bool, private: bool) -> Result<()> {
    check_mode(f, dir, private, false)
}
fn check_mode(f: &File, dir: bool, private: bool, sudo: bool) -> Result<()> {
    let m = f.metadata()?;
    if m.uid() != 0
        || m.gid() != 0
        || m.is_dir() != dir
        || (!dir && (!m.is_file() || m.nlink() != 1))
        || m.mode() & if sudo { 0o3022 } else { 0o7022 } != 0
        || (private && m.mode() & 0o077 != 0)
    {
        return fail("unsafe ownership, mode, link count or file type");
    }
    no_acl(f)
}
/// Traverse every component with openat + NOFOLLOW, never accept symlink parents.
pub fn open(path: &str, dir: bool, private: bool) -> Result<File> {
    open_mode(path, dir, private, false)
}
fn open_mode(path: &str, dir: bool, private: bool, sudo: bool) -> Result<File> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return fail("absolute protected path required");
    }
    let mut parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/")?;
    check(&parent, true, false)?;
    let parts: Vec<_> = p.components().collect();
    for (i, c) in parts.iter().enumerate() {
        let Component::Normal(name) = c else {
            if matches!(c, Component::RootDir) {
                continue;
            }
            return fail("invalid protected path");
        };
        let last = i == parts.len() - 1;
        let d = !last || dir;
        let n = CString::new(name.as_encoded_bytes())?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                n.as_ptr(),
                libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | if d {
                        libc::O_DIRECTORY
                    } else {
                        libc::O_NONBLOCK
                    },
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        parent = unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) };
        check_mode(&parent, d, last && private, last && sudo)?;
    }
    Ok(parent)
}
pub fn read(path: &str, max: u64, private: bool) -> Result<Vec<u8>> {
    use std::io::Read;
    let f = open(path, false, private)?;
    let mut b = Vec::new();
    f.take(max + 1).read_to_end(&mut b)?;
    if b.len() as u64 > max {
        return fail("protected file exceeds limit");
    }
    Ok(b)
}
pub fn installed() -> Result<()> {
    let current = std::fs::metadata("/proc/self/exe")?;
    let installed = open(crate::HELPER, false, false)?.metadata()?;
    if current.ino() != installed.ino() || current.dev() != installed.dev() {
        return fail("stale or uninstalled helper");
    }
    open(crate::FRONTEND, false, false)?;
    Ok(())
}
pub fn audit(event: &str, actor: u32, id: &str, exe: Option<&str>) {
    audit_recipient(event, actor, None, id, exe)
}
pub fn audit_recipient(
    event: &str,
    actor: u32,
    recipient: Option<u32>,
    id: &str,
    exe: Option<&str>,
) {
    let msg = format!(
        "agent-sudo event={event} actor_uid={actor} grant={id} time={} recipient_uid={:?} exe={}",
        walltime(),
        recipient,
        serde_json::to_string(&exe).unwrap_or_default()
    );
    if let Ok(s) = CString::new(msg) {
        unsafe {
            libc::syslog(
                libc::LOG_AUTHPRIV | libc::LOG_NOTICE,
                c"%s".as_ptr(),
                s.as_ptr(),
            );
        }
    }
}
pub fn nonblock(fd: i32) -> Result<()> {
    let f = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if f < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, f | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Sudo itself is intentionally setuid; retain all other integrity checks.
pub fn read_sudo(path: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let f = open_mode(path, false, false, true)?;
    let mut b = Vec::new();
    f.take(16_777_217).read_to_end(&mut b)?;
    if b.len() > 16_777_216 {
        return fail("sudo executable too large");
    }
    Ok(b)
}

/// A single regular child of an already verified root directory. No parent links
/// or caller-selected path traversal are possible, including on create paths.
pub fn child(dir: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return fail("invalid protected child name");
    }
    check(dir, true, false)?;
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let f: File = unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) };
    check(&f, false, true)?;
    Ok(f)
}
pub fn unlink(dir: &File, name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return fail("invalid protected child name");
    }
    check(dir, true, false)?;
    let name = CString::new(name)?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    dir.sync_all()?;
    Ok(())
}
