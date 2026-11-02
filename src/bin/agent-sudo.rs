use agent_sudo::{HELPER, Result, fail, protocol as p, security as s};
use std::{
    fs::{File, OpenOptions},
    io::{IsTerminal, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicI32, Ordering},
    },
};
use zeroize::{Zeroize, Zeroizing};
static INPUT_ERROR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static RESULT_FD: AtomicI32 = AtomicI32::new(-1);
static FINAL: Mutex<Option<serde_json::Value>> = Mutex::new(None);
static SIGNAL: AtomicI32 = AtomicI32::new(0);
static SUDO_PID: AtomicI32 = AtomicI32::new(0);
extern "C" fn signal(sig: i32) {
    SIGNAL.store(sig, Ordering::SeqCst);
    let pid = SUDO_PID.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}
struct Echo {
    fd: i32,
    old: libc::termios,
}
impl Drop for Echo {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.old);
        }
    }
}
fn tty_line(prompt: &str, hidden: bool) -> Result<Zeroizing<String>> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
        .open("/dev/tty")?;
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;
    let mut old = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(tty.as_raw_fd(), old.as_mut_ptr()) } != 0 {
        return fail("terminal unavailable");
    }
    let old = unsafe { old.assume_init() };
    let _guard = Echo {
        fd: tty.as_raw_fd(),
        old,
    };
    if hidden {
        let mut new = old;
        new.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(tty.as_raw_fd(), libc::TCSANOW, &new) } != 0 {
            return fail("cannot disable echo");
        }
    }
    let result = read_line(&mut tty, if hidden { 110 } else { 128 });
    if hidden {
        let _ = tty.write_all(b"\n");
    }
    result
}
fn read_line(file: &mut impl Read, limit: usize) -> Result<Zeroizing<String>> {
    let mut b = Zeroizing::new(Vec::new());
    loop {
        let mut c = [0];
        let n = file.read(&mut c)?;
        if n == 0 || c[0] == b'\n' {
            break;
        }
        if b.len() >= limit {
            return fail("input too long");
        }
        b.push(c[0]);
    }
    if b.last() == Some(&b'\r') {
        b.pop();
    }
    Ok(Zeroizing::new(
        std::str::from_utf8(&b)
            .map_err(|_| "input must be UTF-8")?
            .to_owned(),
    ))
}
fn help() {
    println!(
        "agent-sudo {}\n\nTemporary arbitrary root commands for an enrolled local account.\n\nagent-sudo                              Interactive grant\nagent-sudo grant --user USER --minutes 1..1440\nagent-sudo run [--key-fd FD] [--result-fd FD] [--json-result] -- /absolute/program [args]\nagent-sudo status\nagent-sudo revoke GRANT-ID | revoke --all\nagent-sudo admin list | admin revoke GRANT-ID\nagent-sudo --help | --version\n\nRun supports piped binary streams, no PTY. Redirect stdin (e.g. </dev/null).\nNo saved administrator passwords. Existing root work survives expiry/revoke.",
        agent_sudo::VERSION
    );
}
fn call(op: &str, mut request: p::Request, key_fd: Option<i32>, json_result: bool) -> Result<i32> {
    // Preflight policy before reading token; actual run rechecks READY before transmission.

    if op == "run" {
        call("preflight", p::Request::empty(), None, false)?;
        let mut t = if let Some(fd) = key_fd {
            let mut f = unsafe { File::from_raw_fd(fd) };
            read_line(&mut f, 110)?
        } else {
            tty_line("Access token: ", true)?
        };
        agent_sudo::store::token(&t)?;
        request.token = Some(std::mem::take(&mut *t));
    }
    let administrative = matches!(op, "grant" | "admin-list" | "admin-revoke");
    let mut child = Command::new("/usr/bin/sudo")
        .args([
            if administrative { "-k" } else { "-n" },
            "--",
            HELPER,
            if op == "preflight" { "status" } else { op },
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    SUDO_PID.store(child.id() as i32, Ordering::SeqCst);
    let mut w = child.stdin.take().ok_or("missing transport")?;
    let mut r = child.stdout.take().ok_or("missing response")?;
    let ready = p::read_frame(&mut r);
    if !matches!(&ready,Ok((b'R',b))if b.is_empty()) {
        SUDO_PID.store(0, Ordering::SeqCst);
        let _ = child.wait();
        return fail("helper unavailable: check enrollment and validated sudo policy");
    }
    p::write_request(&mut w, &request)?;
    request.token.zeroize();
    let transport = Arc::new(Mutex::new(w));
    if op == "run" {
        let (k, b) = p::read_frame(&mut r)?;
        if k != b'A' || !b.is_empty() {
            SUDO_PID.store(0, Ordering::SeqCst);
            let _ = child.wait();
            return fail("command was not authorized");
        }
        let wt = transport.clone();
        std::thread::spawn(move || {
            let mut input = std::io::stdin();
            let mut b = [0; p::CHUNK];
            loop {
                match input.read(&mut b) {
                    Ok(0) => {
                        let _ = p::frame(&mut *wt.lock().unwrap(), 1, b"");
                        break;
                    }
                    Ok(n) => {
                        if p::frame(&mut *wt.lock().unwrap(), 0, &b[..n]).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        INPUT_ERROR.store(true, Ordering::SeqCst);
                        let _ = p::frame(&mut *wt.lock().unwrap(), 1, b"");
                        break;
                    }
                }
            }
        });
    }
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let result = (|| -> Result<i32> {
        loop {
            let (kind, bytes) = p::read_frame(&mut r)?;
            let mut data = Zeroizing::new(bytes);
            match kind {
                b'O' => stdout.write_all(&data)?,
                b'E' => stderr.write_all(&data)?,
                b'J' => {
                    if op == "grant" {
                        let mut v: serde_json::Value = serde_json::from_slice(&data)?;
                        let id = v["id"].as_str().ok_or("missing grant ID")?.to_owned();
                        let token =
                            Zeroizing::new(v["token"].as_str().ok_or("missing token")?.to_owned());
                        if let Some(serde_json::Value::String(t)) = v.get_mut("token") {
                            t.zeroize();
                        }
                        eprintln!(
                            "Grant {id}: host {}, recipient {}, expires {}. Revoke: agent-sudo revoke {id}",
                            v["host"], v["recipient"], v["expires_utc"]
                        );
                        writeln!(stdout, "{}", *token)?;
                        stdout.flush()?;
                        data.zeroize();
                        transport
                            .lock()
                            .map_err(|_| "transport lock failed")?
                            .write_all(&[6])?;
                    } else if op != "preflight" {
                        stdout.write_all(&data)?;
                        stdout.write_all(b"\n")?;
                    }
                }
                b'X' => {
                    let v: serde_json::Value = serde_json::from_slice(&data)?;
                    if op != "preflight" {
                        *FINAL.lock().map_err(|_| "result lock")? = Some(v.clone());
                    }
                    if json_result && v["kind"] == "exit" {
                        stderr.write_all(&data)?;
                        stderr.write_all(b"\n")?;
                    }
                    if v["kind"] == "error" {
                        return fail("helper rejected operation");
                    }
                    if v["kind"] != "exit" {
                        return fail("invalid final response");
                    }
                    let code = if let Some(s) = v["signal"].as_i64() {
                        128 + s
                    } else {
                        v["code"].as_i64().ok_or("missing exit status")?
                    };
                    return Ok(code.min(255) as i32);
                }
                _ => return fail("unexpected helper response"),
            }
        }
    })();
    drop(transport);
    if result.is_err() {
        let _ = child.kill();
    }
    SUDO_PID.store(0, Ordering::SeqCst);
    let status = child.wait()?;
    if INPUT_ERROR.load(Ordering::SeqCst) {
        return fail("command input read failed");
    }
    if !status.success() {
        return fail("sudo/helper failed or stream incomplete");
    }
    result
}
fn real() -> Result<i32> {
    s::harden()?;
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = signal as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|x| {
            x.into_string()
                .map_err(|_| "non-UTF-8 arguments unsupported")
        })
        .collect::<std::result::Result<_, _>>()?;
    if args == ["--version"] {
        println!("agent-sudo {}", agent_sudo::VERSION);
        return Ok(0);
    }
    if args == ["--help"] {
        help();
        return Ok(0);
    }
    let mut r = p::Request::empty();
    let mut key = None;
    let mut json = false;
    let op = if args.is_empty() {
        eprintln!(
            "This grants arbitrary root commands. Root work and persistence can outlive expiry. Normal sudo authentication follows; passwordless host policy may not challenge."
        );
        let default = std::env::var("USER").unwrap_or_default();
        let u = tty_line(&format!("Recipient [{default}]: "), false)?;
        r.user = Some(if u.is_empty() { default } else { u.to_string() });
        let m = tty_line("Minutes [60]: ", false)?;
        r.minutes = Some(if m.is_empty() { 60 } else { m.parse()? });
        "grant"
    } else {
        match args[0].as_str() {
            "grant" => {
                let mut i = 1;
                while i < args.len() {
                    let v = args.get(i + 1).ok_or("missing grant value")?;
                    match args[i].as_str() {
                        "--user" if r.user.is_none() => r.user = Some(v.clone()),
                        "--minutes" if r.minutes.is_none() => r.minutes = Some(v.parse()?),
                        _ => return fail("invalid grant option"),
                    };
                    i += 2;
                }
                eprintln!(
                    "Arbitrary root access; admitted work survives expiry. Normal sudo authentication requested; passwordless policy may not challenge."
                );
                "grant"
            }
            "run" => {
                let mut i = 1;
                while i < args.len() && args[i] != "--" {
                    match args[i].as_str() {
                        "--key-fd" if key.is_none() => {
                            i += 1;
                            let fd: i32 = args.get(i).ok_or("missing key descriptor")?.parse()?;
                            if fd < 3 {
                                return fail("key fd must be >=3 and separate from command stdin");
                            }
                            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                            if flags < 0
                                || unsafe {
                                    libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC)
                                } < 0
                            {
                                return fail("invalid key descriptor");
                            }
                            key = Some(fd);
                        }
                        "--result-fd" if RESULT_FD.load(Ordering::SeqCst) < 0 => {
                            i += 1;
                            let fd: i32 =
                                args.get(i).ok_or("missing result descriptor")?.parse()?;
                            if fd < 3 {
                                return fail("result fd must be >=3");
                            }
                            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                            if flags < 0
                                || unsafe {
                                    libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC)
                                } < 0
                            {
                                return fail("invalid result descriptor");
                            }
                            RESULT_FD.store(fd, Ordering::SeqCst);
                        }
                        "--json-result" if !json => json = true,
                        _ => return fail("invalid run option"),
                    };
                    i += 1;
                }
                if args.get(i).map(String::as_str) != Some("--") {
                    return fail("run requires -- before executable");
                }
                r.argv = Some(args[i + 1..].to_vec());
                r.token = Some(String::new());
                if std::io::stdin().is_terminal() {
                    return fail(
                        "PTY execution unsupported; redirect command stdin, e.g. </dev/null",
                    );
                }
                "run"
            }
            "status" if args.len() == 1 => "status",
            "revoke" if args.len() == 2 => {
                if args[1] == "--all" {
                    "revoke-all"
                } else {
                    r.id = Some(args[1].clone());
                    "revoke"
                }
            }
            "admin" if args.len() == 2 && args[1] == "list" => "admin-list",
            "admin" if args.len() == 3 && args[1] == "revoke" => {
                r.id = Some(args[2].clone());
                "admin-revoke"
            }
            _ => return fail("invalid command; use --help"),
        }
    };
    if key == Some(RESULT_FD.load(Ordering::SeqCst)) {
        return fail("key and result descriptors must differ");
    }
    r.validate(op)?;
    call(op, r, key, json)
}
fn main() {
    let result = real();
    let value = match &result {
        Ok(_) => FINAL.lock().ok().and_then(|v| v.clone()),
        Err(e) => Some(serde_json::json!({"kind":"error","message":e.to_string()})),
    };
    let fd = RESULT_FD.swap(-1, Ordering::SeqCst);
    if fd >= 3 {
        let mut f = unsafe { File::from_raw_fd(fd) };
        if let Some(v) = &value
            && writeln!(f, "{v}").is_err()
        {
            eprintln!("agent-sudo: result delivery failed");
            std::process::exit(125);
        }
    }
    match result {
        Ok(n) => std::process::exit(n),
        Err(e) => {
            if std::env::args_os().any(|a| a == "--json-result") {
                eprintln!(
                    "{}",
                    serde_json::json!({"kind":"error","message":e.to_string()})
                );
            }
            eprintln!("agent-sudo: {e}");
            std::process::exit(125);
        }
    }
}
