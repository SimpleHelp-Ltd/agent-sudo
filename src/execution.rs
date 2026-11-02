use crate::{Result, fail, protocol as p, security as s};
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::process::{CommandExt, ExitStatusExt},
    },
    process::{Command, Stdio},
    time::{Duration, Instant},
};
fn pollfds(fds: &mut [libc::pollfd]) -> Result<()> {
    let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 50) };
    if n < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn write_pending(fd: &mut impl Write, buf: &mut Vec<u8>) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    match fd.write(buf) {
        Ok(0) => fail("closed output"),
        Ok(n) => {
            buf.drain(..n);
            Ok(())
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}
static PENDING_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
static CHILD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
extern "C" fn forward(sig: i32) {
    let pid = CHILD.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            libc::kill(-pid, sig);
        }
    } else {
        PENDING_SIGNAL.store(sig, std::sync::atomic::Ordering::SeqCst);
    }
}
struct Guard {
    pid: i32,
    armed: bool,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if self.armed {
            unsafe {
                libc::kill(-self.pid, libc::SIGTERM);
            }
        }
    }
}
pub fn run(argv: &[String], input: &mut File, out: &mut File) -> Result<()> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .env_clear()
        .env("HOME", "/root")
        .env("USER", "root")
        .env("LOGNAME", "root")
        .env("SHELL", "/bin/sh")
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LANG", "C.UTF-8")
        .current_dir("/root")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0
                || libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(0, 0, 0) != 0
                || libc::setresuid(0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            libc::umask(0o077);
            for sig in [libc::SIGPIPE, libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                libc::signal(sig, libc::SIG_DFL);
            } // CLOEXEC retains Rust's exec-failure pipe until exec; no descriptor survives successful exec.
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        unsafe {
            libc::signal(sig, forward as *const () as usize);
        }
    }
    let mut child = cmd.spawn()?;
    let pid = child.id() as i32;
    let mut guard = Guard { pid, armed: true };
    CHILD.store(pid, std::sync::atomic::Ordering::SeqCst);
    let signal = PENDING_SIGNAL.swap(0, std::sync::atomic::Ordering::SeqCst);
    if signal != 0 {
        unsafe {
            libc::kill(-pid, signal);
        }
    }
    let mut sin = child.stdin.take();
    let mut sout = child.stdout.take().ok_or("missing child stdout")?;
    let mut serr = child.stderr.take().ok_or("missing child stderr")?;
    for fd in [
        input.as_raw_fd(),
        out.as_raw_fd(),
        sout.as_raw_fd(),
        serr.as_raw_fd(),
        sin.as_ref().ok_or("missing child stdin")?.as_raw_fd(),
    ] {
        s::nonblock(fd)?;
    }
    let mut incoming = Vec::with_capacity(p::CHUNK + 5);
    let mut pending = Vec::new();
    let mut response = Vec::new();
    let mut eof = false;
    let mut in_done = false;
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut exited = false;
    let mut exit_at = None;
    loop {
        if !exited {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as u32,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            exited = unsafe { info.si_pid() } != 0;
            if exited {
                exit_at = Some(Instant::now());
                sin.take();
                pending.clear();
            }
        }
        if response.is_empty() && stdout_done && stderr_done && exited {
            break;
        }
        let mut fds = [
            libc::pollfd {
                fd: input.as_raw_fd(),
                events: if !in_done && pending.is_empty() && incoming.len() < p::CHUNK + 5 {
                    libc::POLLIN
                } else {
                    0
                },
                revents: 0,
            },
            libc::pollfd {
                fd: out.as_raw_fd(),
                events: if response.is_empty() {
                    0
                } else {
                    libc::POLLOUT
                },
                revents: 0,
            },
            libc::pollfd {
                fd: sout.as_raw_fd(),
                events: if !stdout_done && response.len() < 65536 {
                    libc::POLLIN
                } else {
                    0
                },
                revents: 0,
            },
            libc::pollfd {
                fd: serr.as_raw_fd(),
                events: if !stderr_done && response.len() < 32768 {
                    libc::POLLIN
                } else {
                    0
                },
                revents: 0,
            },
            libc::pollfd {
                fd: sin.as_ref().map(AsRawFd::as_raw_fd).unwrap_or(-1),
                events: if pending.is_empty() { 0 } else { libc::POLLOUT },
                revents: 0,
            },
        ];
        pollfds(&mut fds)?;
        if fds[1].revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            return fail("frontend output disconnected");
        }
        if fds[1].revents & libc::POLLOUT != 0 {
            write_pending(out, &mut response)?;
        }
        if fds[4].revents != 0
            && let Some(w) = sin.as_mut()
        {
            match write_pending(w, &mut pending) {
                Ok(()) => {}
                Err(_) => {
                    sin.take();
                    pending.clear();
                }
            }
        }
        if eof && pending.is_empty() {
            sin.take();
        }
        if fds[0].events != 0 && fds[0].revents != 0 {
            let mut buf = [0; p::CHUNK + 5];
            let space = (p::CHUNK + 5) - incoming.len();
            match input.read(&mut buf[..space]) {
                Ok(0) => {
                    if !eof {
                        return fail("frontend input disconnected");
                    }
                    if !incoming.is_empty() {
                        return fail("truncated input stream frame");
                    }
                    in_done = true;
                }
                Ok(n) => incoming.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }
        if pending.is_empty() && incoming.len() >= 5 {
            let n = u32::from_be_bytes(incoming[1..5].try_into()?) as usize;
            if n > p::CHUNK {
                return fail("input frame exceeds bound");
            }
            if incoming.len() >= n + 5 {
                let kind = incoming[0];
                match kind {
                    0 if !eof => {
                        if sin.is_some() {
                            pending.extend_from_slice(&incoming[5..5 + n]);
                        }
                    }
                    1 if n == 0 && !eof => eof = true,
                    2 if n == 1 => {
                        let sig = incoming[5] as i32;
                        if !matches!(sig, libc::SIGINT | libc::SIGTERM | libc::SIGHUP) {
                            return fail("unsupported signal");
                        }
                        unsafe {
                            libc::kill(-pid, sig);
                        }
                    }
                    _ => return fail("invalid input stream frame"),
                };
                incoming.drain(..n + 5);
            }
        }
        for (index, reader, done, kind) in [
            (2, &mut sout as &mut dyn Read, &mut stdout_done, b'O'),
            (3, &mut serr as &mut dyn Read, &mut stderr_done, b'E'),
        ] {
            // A closed leader may leave background pipes open. Only cut an idle
            // pipe after the grace period; never discard buffered data under backpressure.
            if !*done
                && fds[index].events != 0
                && fds[index].revents == 0
                && exit_at.is_some_and(|at| at.elapsed() > Duration::from_secs(2))
            {
                *done = true;
            }
            if !*done && fds[index].events != 0 && fds[index].revents != 0 {
                let mut b = [0; 16384];
                match reader.read(&mut b) {
                    Ok(0) => *done = true,
                    Ok(n) => response.extend_from_slice(&p::packet(kind, &b[..n])),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    CHILD.store(0, std::sync::atomic::Ordering::SeqCst);
    guard.armed = false;
    let status = child.wait()?;
    // Restore blocking output for short final frame after all stream bytes.
    unsafe {
        let flags = libc::fcntl(out.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(out.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }
    p::json(
        out,
        b'X',
        &serde_json::json!({"kind":"exit","code":status.code(),"signal":status.signal()}),
    )?;
    Ok(())
}
