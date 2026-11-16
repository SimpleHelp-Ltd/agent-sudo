// Copyright 2026 SimpleHelp
// SPDX-License-Identifier: Apache-2.0

use crate::{Result, fail};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, ZeroizeOnDrop};
pub const MAX: usize = 65536;
pub const CHUNK: usize = 32768;
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: u32,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub minutes: Option<u32>,
    #[serde(default)]
    pub id: Option<String>,
}
impl Request {
    pub fn empty() -> Self {
        Self {
            v: 1,
            token: None,
            argv: None,
            user: None,
            minutes: None,
            id: None,
        }
    }
    pub fn validate(&self, op: &str) -> Result<()> {
        if self.v != 1 {
            return fail("unsupported protocol version");
        }
        let fields = (
            self.token.is_some(),
            self.argv.is_some(),
            self.user.is_some(),
            self.minutes.is_some(),
            self.id.is_some(),
        );
        let wanted = match op {
            "run" => (true, true, false, false, false),
            "grant" => (false, false, true, true, false),
            "revoke" | "admin-revoke" => (false, false, false, false, true),
            "status" | "revoke-all" | "admin-list" | "admin-revoke-created" | "cleanup" => {
                (false, false, false, false, false)
            }
            _ => return fail("invalid operation"),
        };
        if fields != wanted {
            return fail("invalid fields for operation");
        }
        if let Some(args) = &self.argv
            && (args.is_empty()
                || args.len() > 256
                || args.iter().map(|a| a.len() + 1).sum::<usize>() > 32768
                || args.iter().any(|a| a.len() > 4096 || a.contains('\0'))
                || !args[0].starts_with('/'))
        {
            return fail("invalid argument vector: absolute executable required");
        }
        if let Some(u) = &self.user {
            crate::security::valid_user(u)?;
        }
        if let Some(m) = self.minutes
            && !(1..=1440).contains(&m)
        {
            return fail("minutes must be 1..1440");
        }
        if let Some(id) = &self.id {
            crate::store::valid_id(id)?;
        }
        if let Some(t) = &self.token
            && t.len() > 110
        {
            return fail("invalid token");
        }
        Ok(())
    }
}
pub fn parse(bytes: &[u8], op: &str) -> Result<Request> {
    if bytes.is_empty() || bytes.len() > MAX {
        return fail("invalid header length");
    }
    let r: Request = serde_json::from_slice(bytes)?;
    r.validate(op)?;
    Ok(r)
}
pub fn timed_exact(file: &mut std::fs::File, mut out: &mut [u8], end: Instant) -> Result<()> {
    while !out.is_empty() {
        let remain = end.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            return fail("request deadline exceeded");
        }
        let mut p = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut p, 1, remain.as_millis().min(i32::MAX as u128) as i32) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        if n == 0 {
            return fail("request deadline exceeded");
        }
        let n = file.read(out)?;
        if n == 0 {
            return fail("truncated request");
        }
        out = &mut out[n..];
    }
    Ok(())
}
pub fn read_request(input: &mut std::fs::File, op: &str) -> Result<Request> {
    let end = Instant::now() + Duration::from_secs(5);
    let mut len = [0; 4];
    timed_exact(input, &mut len, end)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX {
        return fail("invalid header length");
    }
    let mut b = zeroize::Zeroizing::new(vec![0; len]);
    timed_exact(input, &mut b, end)?;
    parse(&b, op)
}
pub fn write_request(w: &mut impl Write, r: &Request) -> Result<()> {
    let b = zeroize::Zeroizing::new(serde_json::to_vec(r)?);
    if b.len() > MAX {
        return fail("header too long");
    }
    w.write_all(&(b.len() as u32).to_be_bytes())?;
    w.write_all(&b)?;
    w.flush()?;
    Ok(())
}
pub fn packet(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + data.len());
    v.push(kind);
    v.extend_from_slice(&(data.len() as u32).to_be_bytes());
    v.extend_from_slice(data);
    v
}
pub fn frame(w: &mut impl Write, kind: u8, data: &[u8]) -> Result<()> {
    if data.len() > MAX {
        return fail("frame too long");
    }
    w.write_all(&packet(kind, data))?;
    w.flush()?;
    Ok(())
}
pub fn read_frame(r: &mut impl Read) -> Result<(u8, Vec<u8>)> {
    let mut h = [0; 5];
    r.read_exact(&mut h)?;
    let n = u32::from_be_bytes(h[1..].try_into()?) as usize;
    if n > MAX {
        return fail("response frame too long");
    }
    let mut b = vec![0; n];
    r.read_exact(&mut b)?;
    Ok((h[0], b))
}
pub fn json(w: &mut impl Write, kind: u8, value: &impl Serialize) -> Result<()> {
    let b = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
    frame(w, kind, &b)
}
/// Bounded privileged control output. A hostile reader cannot pin helper slots forever.
pub fn file_frame(w: &mut std::fs::File, kind: u8, data: &[u8]) -> Result<()> {
    if data.len() > MAX {
        return fail("frame too long");
    }
    crate::security::nonblock(w.as_raw_fd())?;
    let b = zeroize::Zeroizing::new(packet(kind, data));
    let mut pending = &b[..];
    let end = Instant::now() + Duration::from_secs(5);
    while !pending.is_empty() {
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return fail("response deadline exceeded");
        }
        let mut p = libc::pollfd {
            fd: w.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let n = unsafe {
            libc::poll(
                &mut p,
                1,
                remaining.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        if n == 0 {
            return fail("response deadline exceeded");
        }
        match w.write(pending) {
            Ok(0) => return fail("response disconnected"),
            Ok(n) => pending = &pending[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
pub fn file_json(w: &mut std::fs::File, kind: u8, value: &impl Serialize) -> Result<()> {
    let b = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
    file_frame(w, kind, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hostile_headers() {
        for b in [
            r#"{"v":1,"v":1}"#.as_bytes(),
            br#"{"v":1,"x":0}"#,
            br#"{"v":1,"token":"a","argv":["relative"]}"#,
            br#"{"v":2}"#,
            br#"{"v":1,"id":"../x"}"#,
        ] {
            assert!(parse(b, "run").is_err());
        }
        assert!(parse(br#"{"v":1}"#, "status").is_ok());
    }
    #[test]
    fn creator_revocation_has_no_caller_selected_fields() {
        assert!(parse(br#"{"v":1}"#, "admin-revoke-created").is_ok());
        for b in [
            br#"{"v":1,"creator":0}"#.as_slice(),
            br#"{"v":1,"user":"root"}"#,
            br#"{"v":1,"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            br#"{"v":1,"token":"x"}"#,
            br#"{"v":1,"minutes":10}"#,
        ] {
            assert!(parse(b, "admin-revoke-created").is_err());
        }
    }
    #[test]
    fn binary_frames() {
        let b: Vec<u8> = (0..=255).collect();
        let f = packet(b'O', &b);
        assert_eq!(read_frame(&mut &f[..]).unwrap(), (b'O', b));
    }
    #[test]
    fn deterministic_parser_mutations() {
        let base = br#"{"v":1,"token":"v1.abc","argv":["/usr/bin/id"]}"#;
        for i in 0..20000 {
            let mut b = base.to_vec();
            let p = i % b.len();
            b[p] = (i / 13) as u8;
            let _ = parse(&b, "run");
        }
        for n in [0, 1, 65536, 65537] {
            let _ = parse(&vec![b'['; n], "run");
        }
    }
}
