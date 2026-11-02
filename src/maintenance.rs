use crate::{CONTROL, FRONTEND, HELPER, RUNTIME, Result, fail, security as s, store};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
};
const POLICY: &str = "/etc/sudoers.d/agent-sudo";
const SERVICE: &str = "[Unit]\nDescription=Remove expired agent-sudo grants\n[Service]\nType=oneshot\nExecStart=/usr/local/libexec/agent-sudo-helper cleanup\nUser=root\nGroup=root\nUMask=0077\n";
const TIMER: &str = "[Unit]\nDescription=Periodic agent-sudo expiry cleanup\n[Timer]\nOnBootSec=60\nOnUnitActiveSec=60\n[Install]\nWantedBy=timers.target\n";
const TMPFILES: &str = "d /run/agent-sudo 0700 root root -\n";
const MANAGED: &[(&str, u32)] = &[
    (FRONTEND, 0o755),
    (HELPER, 0o755),
    (POLICY, 0o440),
    ("/etc/systemd/system/agent-sudo-cleanup.service", 0o644),
    ("/etc/systemd/system/agent-sudo-cleanup.timer", 0o644),
    ("/etc/tmpfiles.d/agent-sudo.conf", 0o644),
];
fn output(cmd: &mut Command) -> Result<String> {
    let o = cmd
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .output()?;
    if !o.status.success() {
        return fail(&format!(
            "administrative subprocess failed: {}",
            String::from_utf8_lossy(&o.stderr)
        ));
    }
    Ok(String::from_utf8(o.stdout)?)
}
pub fn sudo_version() -> Result<String> {
    let v = output(Command::new("/usr/bin/sudo").arg("--version"))?;
    let first = v.lines().next().ok_or("missing sudo version")?.to_owned();
    if !(first.starts_with("Sudo version 1.9.15p5") || first.starts_with("sudo-rs 0.2.13")) {
        return fail(
            "unsupported sudo version: locally validated builds are traditional 1.9.15p5 and sudo-rs 0.2.13",
        );
    }
    Ok(first)
}
fn root_file(path: &str) -> Result<String> {
    Ok(String::from_utf8(s::read(path, 1_048_576, false)?)?)
}
pub fn policy_snapshot() -> Result<Vec<(String, String)>> {
    let mut paths = vec!["/etc/sudoers".to_owned()];
    for optional in ["/etc/sudo.conf", "/etc/sudoers-rs"] {
        if Path::new(optional).symlink_metadata().is_ok() {
            paths.push(optional.into());
        }
    }
    s::open("/etc/sudoers.d", true, false)?;
    for e in std::fs::read_dir("/etc/sudoers.d")? {
        let e = e?;
        let n = e
            .file_name()
            .into_string()
            .map_err(|_| "invalid sudoers filename")?;
        if paths.len() > 256 {
            return fail("too many sudo policy files");
        }
        paths.push(format!("/etc/sudoers.d/{n}"));
    }
    paths.sort();
    let mut out = Vec::new();
    let mut total = 0usize;
    for p in paths {
        let b = root_file(&p)?;
        total += b.len();
        if total > 1_048_576 {
            return fail("total sudo policy exceeds 1 MiB");
        }
        if p == "/etc/sudo.conf" {
            for l in b.lines() {
                if l.ends_with('\\') {
                    return fail("continued sudo policy lines unsupported");
                }
                let l = l.trim();
                if !l.is_empty() && !l.starts_with('#') {
                    return fail("custom sudo.conf plugins/settings unsupported");
                }
            }
        } else {
            for l in b.lines() {
                if l.ends_with('\\') {
                    return fail("continued sudo policy lines unsupported");
                }
                let l = l.trim();
                if p != POLICY
                    && l.strip_prefix("Defaults")
                        .is_some_and(|x| x.trim_start().starts_with('!'))
                {
                    return fail(
                        "external command-scoped Defaults unsupported: may override helper transport/logging",
                    );
                }
                if (l.starts_with("@include") || l.starts_with("#include"))
                    && l != "@includedir /etc/sudoers.d"
                    && l != "#includedir /etc/sudoers.d"
                {
                    return fail("external sudo policy includes unsupported");
                }
                if !l.starts_with('#') {
                    let normalized = l.replace("NOLOG_INPUT", "").replace("NOLOG_OUTPUT", "");
                    if normalized.contains("LOG_INPUT")
                        || normalized.contains("LOG_OUTPUT")
                        || normalized.contains("INTERCEPT")
                        || l.contains("log_servers")
                        || l.contains("log_subcmds")
                        || l.contains("intercept")
                        || l.contains("log_ttyin")
                        || l.contains("log_stdin")
                        || l.contains("log_stdout")
                        || l.contains("log_stderr")
                        || l.contains("log_ttyout")
                    {
                        return fail("unsupported sudo recording/command tags");
                    }
                }
            }
        }
        out.push((p, s::hash(b.as_bytes())));
    }
    for p in ["/usr/bin/sudo", "/usr/sbin/visudo"] {
        let target = std::fs::canonicalize(p)?;
        let canonical = target.to_str().ok_or("non-UTF8 sudo path")?;
        let b = s::read_sudo(canonical)?;
        out.push((format!("{p}=>{canonical}"), s::hash(&b)));
    }
    out.push(("sudo-version".into(), sudo_version()?));
    Ok(out)
}
pub fn policy(accounts: &[s::Account], rs: bool) -> String {
    let mut p = String::from(
        "# agent-sudo managed v1\nDefaults!/usr/local/libexec/agent-sudo-helper !use_pty",
    );
    if !rs {
        p.push_str(", !log_input, !log_output");
    }
    p.push('\n');
    for a in accounts {
        p.push_str(&format!("{} ALL=(root) NOPASSWD: NOSETENV: {HELPER} run, {HELPER} status, {HELPER} revoke, {HELPER} revoke-all\n",a.name));
    }
    p
}
pub fn atomic(path: &str, b: &[u8], mode: u32) -> Result<()> {
    let p = Path::new(path);
    let parent = p
        .parent()
        .ok_or("missing parent")?
        .to_str()
        .ok_or("invalid path")?;
    let d = s::open(parent, true, parent == CONTROL || parent == RUNTIME)?;
    if p.symlink_metadata().is_ok() {
        s::open(path, false, false)?;
    }
    let temp = format!("{parent}/.agent-sudo-{}", s::random(16)?);
    let r = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        f.write_all(b)?;
        f.sync_all()?;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode))?;
        std::fs::rename(&temp, path)?;
        d.sync_all()?;
        Ok(())
    })();
    let _ = std::fs::remove_file(temp);
    r
}
fn visudo() -> Result<()> {
    output(Command::new("/usr/sbin/visudo").arg("-c"))?;
    Ok(())
}
fn systemctl(args: &[&str]) -> Result<()> {
    output(Command::new("/usr/bin/systemctl").args(args))?;
    Ok(())
}
pub fn probe() -> Result<()> {
    let actor = s::actor()?;
    if actor.uid != 0 {
        return fail("probe is root-only");
    }
    let mut b = Vec::new();
    std::io::stdin().take(1_048_577).read_to_end(&mut b)?;
    if b.len() > 1_048_576 {
        return fail("probe too large");
    }
    std::io::stdout().write_all(&b)?;
    std::io::stderr().write_all(b"agent-sudo-probe-stderr\0\xff")?;
    Ok(())
}
fn transport() -> Result<()> {
    let mut ch = Command::new("/usr/bin/sudo")
        .args(["-n", "--", HELPER, "probe"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let b: Vec<u8> = (0..=255).cycle().take(65536).collect();
    let mut w = ch.stdin.take().ok_or("probe stdin")?;
    let data = b.clone();
    let writer = std::thread::spawn(move || w.write_all(&data));
    let o = ch.wait_with_output()?;
    writer.join().map_err(|_| "probe writer panic")??;
    if !o.status.success() || o.stdout != b || o.stderr != b"agent-sudo-probe-stderr\0\xff" {
        return fail("sudo transport probe failed");
    }
    Ok(())
}
fn manifest() -> Result<Vec<(String, String)>> {
    Ok(serde_json::from_slice(&s::read(
        &format!("{CONTROL}/manifest"),
        16384,
        true,
    )?)?)
}
fn existing() -> Result<bool> {
    if !Path::new(&format!("{CONTROL}/manifest")).exists() {
        for (p, _) in MANAGED {
            if Path::new(p).symlink_metadata().is_ok() {
                return fail("conflicting unmanaged installation file");
            }
        }
        return Ok(false);
    }
    let entries = manifest()?;
    if entries.len() != MANAGED.len()
        || entries
            .iter()
            .zip(MANAGED)
            .any(|((p, _), (expected, _))| p != expected)
    {
        return fail("invalid managed file manifest");
    }
    for (p, h) in entries {
        if s::hash(&s::read(&p, 16_777_216, false)?) != h {
            return fail("managed file changed: recover with independent administrator");
        }
    }
    Ok(true)
}
pub fn install(from: &str, users: &[String]) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getuid() } != 0 {
        return fail("installation requires root through normal administrator sudo");
    }
    if users.is_empty() || users.len() > 128 {
        return fail("select 1..128 explicit --user accounts");
    }
    let mut accounts = Vec::new();
    for u in users {
        let a = s::account(u)?;
        if a.uid == 0 || accounts.iter().any(|x: &s::Account| x.uid == a.uid) {
            return fail("duplicate/root enrollment unsupported");
        }
        accounts.push(a);
    }
    // Freeze payload bytes before making changes. It is code deliberately selected by an administrator.
    let mut payload = Vec::new();
    for (n, _) in &MANAGED[..2] {
        let name = Path::new(n).file_name().ok_or("payload name")?;
        let p = Path::new(from).join(name);
        let mut b = Vec::new();
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(p)?;
        if !f.metadata()?.is_file() {
            return fail("payload must be regular file");
        }
        f.take(16_777_217).read_to_end(&mut b)?;
        if b.len() > 16_777_216 || !b.starts_with(b"\x7fELF") {
            return fail("invalid executable payload");
        }
        payload.push(b);
    }
    s::open("/var/lib", true, false)?;
    store::ensure_dir(CONTROL)?;
    let lock_path = format!("{CONTROL}/lock");
    let _initial = store::file_rw(&lock_path, true)?;
    let _l = store::lock()?;
    let existed = existing()?;
    for dir in ["/usr/local/bin", "/usr/local/libexec", "/etc/tmpfiles.d"] {
        if !Path::new(dir).exists() {
            let parent = Path::new(dir)
                .parent()
                .ok_or("parent")?
                .to_str()
                .ok_or("path")?;
            s::open(parent, true, false)?;
            std::fs::create_dir(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
        }
        s::open(dir, true, false)?;
    }
    let os_path = std::fs::canonicalize("/etc/os-release")?;
    let os = root_file(os_path.to_str().ok_or("non-UTF8 OS metadata path")?)?;
    if !os.lines().any(|l| l == "ID=ubuntu")
        || !os
            .lines()
            .any(|l| matches!(l, "VERSION_ID=\"24.04\"" | "VERSION_ID=\"26.04\""))
        || !Path::new("/run/systemd/system").is_dir()
    {
        return fail("supported platform is Ubuntu 24.04/26.04 with systemd");
    }
    for path in ["/usr/sbin/runuser", "/usr/bin/systemctl"] {
        let p = std::fs::canonicalize(path)?;
        s::open(p.to_str().ok_or("non-UTF8 dependency path")?, false, false)?;
    }
    let version = sudo_version()?;
    visudo()?;
    policy_snapshot()?;
    let new_policy = policy(&accounts, version.starts_with("sudo-rs"));
    let mut backups = Vec::new();
    for (p, mode) in MANAGED {
        let bytes = if Path::new(p).exists() {
            Some(s::read(p, 16_777_216, false)?)
        } else {
            None
        };
        backups.push((*p, *mode, bytes));
    }
    let old_manifest = s::read(&format!("{CONTROL}/manifest"), 16384, true).ok();
    let old_config = s::read(&format!("{CONTROL}/config"), 131072, true).ok();
    let disabled = store::Config {
        v: 1,
        enabled: false,
        generation: s::random(16)?,
        accounts: vec![],
        policy: vec![],
        sudo_version: version.clone(),
    };
    atomic(
        &format!("{CONTROL}/config"),
        &serde_json::to_vec(&disabled)?,
        0o600,
    )?;
    store::invalidate()?;
    if Path::new(POLICY).exists() {
        std::fs::remove_file(POLICY)?;
    }
    let r = (|| {
        atomic(FRONTEND, &payload[0], 0o755)?;
        atomic(HELPER, &payload[1], 0o755)?;
        for (p, b) in [
            (MANAGED[3].0, SERVICE.as_bytes()),
            (MANAGED[4].0, TIMER.as_bytes()),
            (MANAGED[5].0, TMPFILES.as_bytes()),
        ] {
            atomic(p, b, 0o644)?;
        }
        store::ensure_dir(RUNTIME)?;
        store::prune_slots(&accounts)?;
        atomic(POLICY, new_policy.as_bytes(), 0o440)?;
        visudo()?;
        let seals = policy_snapshot()?;
        transport()?;
        // Check effective permission for the exact operation as each recipient, without feeding secrets.
        for a in &accounts {
            let o = Command::new("/usr/sbin/runuser")
                .args([
                    "-u",
                    &a.name,
                    "--",
                    "/usr/bin/sudo",
                    "-n",
                    "-l",
                    "--",
                    HELPER,
                    "status",
                ])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .output()?;
            if !o.status.success() || !o.stderr.is_empty() {
                return fail("effective token-operation policy probe failed");
            }
        }
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "--now", "agent-sudo-cleanup.timer"])?;
        let c = store::Config {
            v: 1,
            enabled: true,
            generation: s::random(16)?,
            accounts,
            policy: seals,
            sudo_version: version,
        };
        atomic(
            &format!("{CONTROL}/config"),
            &serde_json::to_vec(&c)?,
            0o600,
        )?;
        let mut m = Vec::new();
        for (p, _) in MANAGED {
            m.push((p.to_string(), s::hash(&s::read(p, 16_777_216, false)?)));
        }
        atomic(
            &format!("{CONTROL}/manifest"),
            &serde_json::to_vec(&m)?,
            0o600,
        )?;
        Ok(())
    })();
    if let Err(e) = r {
        let mp = format!("{CONTROL}/manifest");
        if let Some(b) = old_manifest {
            atomic(&mp, &b, 0o600)?;
        } else if Path::new(&mp).exists() {
            std::fs::remove_file(mp)?;
        }
        for (p, mode, b) in backups {
            if let Some(b) = b {
                atomic(p, &b, mode)?;
            } else if Path::new(p).exists() {
                std::fs::remove_file(p)?;
            }
        }
        if let Some(b) = old_config {
            atomic(&format!("{CONTROL}/config"), &b, 0o600)?;
        } else {
            atomic(
                &format!("{CONTROL}/config"),
                &serde_json::to_vec(&disabled)?,
                0o600,
            )?;
        }
        let _ = visudo();
        let _ = systemctl(&["daemon-reload"]);
        if !existed {
            let _ = systemctl(&["disable", "--now", "agent-sudo-cleanup.timer"]);
        }
        return Err(e);
    }
    s::audit("install", s::actor()?.uid, "-", None);
    println!(
        "agent-sudo installed; all previous grants invalidated. Enrollment: {}",
        users.join(", ")
    );
    Ok(())
}
pub fn uninstall() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getuid() } != 0 {
        return fail("removal requires administrator root");
    }
    let _l = store::lock()?;
    existing()?;
    let c = store::Config {
        v: 1,
        enabled: false,
        generation: s::random(16)?,
        accounts: vec![],
        policy: vec![],
        sudo_version: String::new(),
    };
    atomic(
        &format!("{CONTROL}/config"),
        &serde_json::to_vec(&c)?,
        0o600,
    )?;
    if Path::new(POLICY).exists() {
        s::open(POLICY, false, false)?;
        std::fs::remove_file(POLICY)?;
    }
    visudo()?;
    systemctl(&["disable", "--now", "agent-sudo-cleanup.timer"])?;
    store::invalidate()?;
    for (p, _) in MANAGED {
        if *p != POLICY && Path::new(p).exists() {
            s::open(p, false, false)?;
            std::fs::remove_file(p)?;
        }
    }
    let m = format!("{CONTROL}/manifest");
    if Path::new(&m).exists() {
        std::fs::remove_file(m)?;
    }
    if Path::new(RUNTIME).exists() {
        for entry in std::fs::read_dir(RUNTIME)? {
            let p = entry?.path();
            s::open(p.to_str().ok_or("invalid runtime name")?, false, true)?;
            std::fs::remove_file(p)?;
        }
        std::fs::remove_dir(RUNTIME)?;
    }
    systemctl(&["daemon-reload"])?;
    s::audit("uninstall", s::actor()?.uid, "-", None);
    println!("Removed managed files and grants; disabled lock tombstone retained at {CONTROL}.");
    Ok(())
}
