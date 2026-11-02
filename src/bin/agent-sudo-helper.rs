use agent_sudo::{Result, execution, fail, maintenance, protocol as p, security as s, store};
use std::{fs::File, io::Write, os::fd::FromRawFd};
use zeroize::Zeroize;
fn operation(op: &str, actor: &s::Account, input: &mut File, out: &mut File) -> Result<()> {
    // Bound helpers before they wait for the maintenance lock or parse policy.
    // Even accounts without a grant share this fixed-size admission namespace.
    let pending = store::pending(actor)?;
    let c = {
        let _l = store::lock()?;
        store::gate(actor, op)?
    };
    p::file_frame(out, b'R', b"")?;
    let mut r = p::read_request(input, op)?;
    let result = (|| {
        let l = store::lock()?;
        let now = store::gate(actor, op)?;
        if c.generation != now.generation {
            return fail("installation changed during request");
        }
        match op {
            "run" => {
                let argv = r.argv.as_ref().ok_or("missing argv")?;
                let id = store::admit(
                    &now,
                    actor,
                    r.token.as_deref().ok_or("missing token")?,
                    &argv[0],
                )?;
                r.token.zeroize();
                drop(l);
                drop(pending);
                p::file_frame(out, b'A', b"")?;
                execution::run(argv, input, out)?;
                s::audit("complete", actor.uid, &id, None);
            }
            "grant" => {
                let (g, mut token) = store::issue(
                    &now,
                    actor,
                    r.user.as_deref().ok_or("missing recipient")?,
                    r.minutes.ok_or("missing duration")?,
                )?;
                let mut metadata = g.metadata();
                metadata["token"] = serde_json::Value::String(std::mem::take(&mut *token));
                drop(l);
                drop(pending);
                let delivered = p::file_json(out, b'J', &metadata).and_then(|_| {
                    let mut ack = [0];
                    p::timed_exact(
                        input,
                        &mut ack,
                        std::time::Instant::now() + std::time::Duration::from_secs(5),
                    )?;
                    if ack != [6] {
                        return fail("grant receipt not acknowledged");
                    }
                    p::file_json(
                        out,
                        b'X',
                        &serde_json::json!({"kind":"exit","code":0,"signal":null}),
                    )
                });
                if let Some(t) = metadata.get_mut("token")
                    && let serde_json::Value::String(t) = t
                {
                    t.zeroize();
                }
                if delivered.is_err() {
                    let _l = store::lock()?;
                    store::revoke(&g.id, actor, true)?;
                }
                delivered?;
            }
            "status" | "admin-list" => {
                let mut list = Vec::new();
                for id in store::ids()? {
                    let g = store::read_grant(&id)?;
                    if op == "admin-list" || (g.uid == actor.uid && g.user == actor.name) {
                        list.push(g.metadata());
                    }
                }
                drop(l);
                p::file_json(out, b'J', &list)?;
                p::file_json(
                    out,
                    b'X',
                    &serde_json::json!({"kind":"exit","code":0,"signal":null}),
                )?;
            }
            "revoke" | "admin-revoke" => {
                store::revoke(
                    r.id.as_deref().ok_or("missing grant ID")?,
                    actor,
                    op == "admin-revoke",
                )?;
                drop(l);
                p::file_json(
                    out,
                    b'X',
                    &serde_json::json!({"kind":"exit","code":0,"signal":null}),
                )?;
            }
            "revoke-all" => {
                for id in store::ids()? {
                    let g = store::read_grant(&id)?;
                    if g.uid == actor.uid && g.user == actor.name {
                        store::revoke(&id, actor, false)?;
                    }
                }
                drop(l);
                p::file_json(
                    out,
                    b'X',
                    &serde_json::json!({"kind":"exit","code":0,"signal":null}),
                )?;
            }
            _ => return fail("invalid operation"),
        }
        Ok(())
    })();
    r.zeroize();
    result
}
fn real() -> Result<()> {
    s::harden()?;
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.into_string().map_err(|_| "non-UTF8 helper arguments"))
        .collect::<std::result::Result<_, _>>()?;
    let actor = s::actor()?;
    if args.get(1).map(String::as_str) == Some("install") {
        let mut from = None;
        let mut users = Vec::new();
        let mut i = 2;
        while i < args.len() {
            let v = args.get(i + 1).ok_or("missing install option")?;
            match args[i].as_str() {
                "--from" => from = Some(v.clone()),
                "--user" => users.push(v.clone()),
                _ => return fail("invalid install option"),
            };
            i += 2;
        }
        return maintenance::install(&from.ok_or("--from required")?, &users);
    }
    if args.len() != 2 {
        return fail("helper requires one exact operation");
    }
    let op = args[1].as_str();
    if op == "uninstall" {
        return maintenance::uninstall();
    }
    if op == "probe" {
        return maintenance::probe();
    }
    if op == "cleanup" {
        if actor.uid != 0 {
            return fail("cleanup is root-only");
        }
        let _l = store::lock()?;
        let c = store::gate(&actor, op)?;
        let mut count = 0;
        for id in store::ids()? {
            let g = store::read_grant(&id)?;
            if store::live(&g, &c, s::boottime()?).is_err() {
                store::revoke(&id, &actor, true)?;
                count += 1;
            }
        }
        s::audit("cleanup", 0, &count.to_string(), None);
        return Ok(());
    }
    if !matches!(
        op,
        "run" | "status" | "revoke" | "revoke-all" | "grant" | "admin-list" | "admin-revoke"
    ) {
        return fail("invalid helper operation");
    }
    let mut input = unsafe { File::from_raw_fd(0) };
    let mut out = unsafe { File::from_raw_fd(1) };
    match operation(op, &actor, &mut input, &mut out) {
        Ok(()) => Ok(()),
        Err(_e) => {
            store::denial(actor.uid);
            // No blocking output after dropping a pending slot. A full hostile
            // error channel gets EOF/tool failure rather than another waiting helper.
            let _ = s::nonblock(std::os::fd::AsRawFd::as_raw_fd(&out));
            let b = serde_json::to_vec(
                &serde_json::json!({"kind":"error","message":"authorization or operation failed; check active grant, token, expiry and installation policy"}),
            )?;
            let _ = out.write(&p::packet(b'X', &b));
            Err("helper operation failed".into())
        }
    }
}
fn main() {
    if let Err(e) = real() {
        // Framed operations never print untrusted parser values or secret-bearing diagnostics.
        let op = std::env::args_os()
            .nth(1)
            .and_then(|a| a.into_string().ok())
            .unwrap_or_default();
        if matches!(op.as_str(), "install" | "uninstall" | "probe" | "cleanup") {
            eprintln!("agent-sudo-helper: {e}");
        }
        std::process::exit(125);
    }
}
