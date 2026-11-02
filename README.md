# agent-sudo

A local Linux tool for a human administrator to delegate **temporary arbitrary root commands** to an authorized account, without sharing an administrator password.

**1.0.1 release. Tested in disposable VMs; Loom 0.2.0 root-command smoke test passed; expiry test pending.**

```sh
curl -fsSL https://tools.simplehelp.io/agent-sudo/install.sh | sh
```

[Public download and installation guide](https://tools.simplehelp.io/agent-sudo.html). The bootstrap installs machine-wide and verifies the pinned package before normal sudo installation. Select the recipient later when issuing a grant. [Website publication workflow](docs/PUBLISHING.md). Separate Rust frontend and privileged helper; tested in disposable Ubuntu VMs. See [validation](docs/VALIDATION.md), [security review](docs/SECURITY_REVIEW.md), [operator guide](docs/OPERATOR.md) and [wire/security design](docs/DESIGN.md).

```sh
# Build locally (Rust toolchain, musl-tools, Python 3)
python3 scripts/build-release.py
# Only inside a disposable test VM, after inspecting/verifying the package:
tar -xzf agent-sudo-1.0.1-linux-amd64.tar.gz
sudo ./install.sh
agent-sudo agent 60
# As recipient: hidden token prompt; command stdin stays separate.
agent-sudo run -- /usr/bin/id </dev/null
agent-sudo status
agent-sudo revoke GRANT-ID
```

`agent-sudo USERNAME` prompts for minutes; bare `agent-sudo` prompts for username and minutes. Enter accepts the calling account and 10 minutes. Give the resulting token privately to the intended agent. Durations are 1–1440 minutes (default 10). The recipient must already exist and be non-root. A successful administrative grant immediately enables that account; installation requires no recipient selection. Grant issuance and administrative commands use normal, freshly requested sudo authentication; passwordless administrator policy may not ask for a password. The application never receives that password.

```text
agent-sudo [USERNAME [MINUTES]]
agent-sudo grant --user USER --minutes MINUTES
agent-sudo run [--key-fd FD] [--result-fd FD] [--json-result] -- /absolute/program [args...]
agent-sudo status
agent-sudo revoke GRANT-ID
agent-sudo revoke --all
agent-sudo admin list
agent-sudo admin revoke GRANT-ID
agent-sudo revoke all  # Revoke grants issued by the calling administrator
agent-sudo --help | --version
```

Redirected grant stdout contains only one token line; a readable account, local expiry/timezone and administrator revocation command go to stderr. Terminal output labels the private token. Detailed machine identity stays in status metadata. Status/list output is JSON metadata without tokens/verifiers. `--key-fd` consumes a token line from a descriptor >=3. Tokens in argv/environment and automatic token files are unsupported. Commands receive binary stdin/stdout/stderr and their actual exit status (signals map to 128+signal). For reliable automation, supply a separate writable `--result-fd`: it receives one JSON final result, distinguishing child code 125 from tool failure. `--json-result` is a convenience on stderr, which remains mixed with arbitrary child stderr; use the separate result descriptor for unambiguous results.

This is **delegated root authority**, not a sandbox. Tokens are bound to a local account, host and boot. Expiry/revocation/reboot stop future admissions. Already admitted processes survive expiry/revocation, and root can establish persistence. Processes sharing a Linux UID are not strongly isolated. Preserve an independent administrator session. No listener, setuid application, daemon command server, saved administrator password or change to unrelated sudo permissions. The existing `ops/grant-agent-sudo.sh` mechanism is separate and untouched.

Supported platforms: Linux amd64, Ubuntu 24.04/26.04 with systemd; traditional sudo 1.9.15p5 or sudo-rs 0.2.13. Policies outside the validated local-file model fail closed. Any sealed sudo-policy change requires administrator reinstallation/revalidation and invalidates all tokens. [Build and reproduce artifacts](docs/BUILD.md). Not an independent security audit.

`agent-sudo revoke all` requests fresh sudo authorization and revokes every stored grant whose creator UID matches the calling account, across all recipients. It works even if you have no grant yourself and succeeds if there are no matching grants. Grants issued by other administrators remain valid, including those issued to you. Use it without a leading `sudo` to retain your own issuer identity; `sudo agent-sudo revoke all` selects root-issued grants. Creator identity uses the recorded numeric UID; revoke before reusing administrator UIDs. The existing `agent-sudo revoke --all` retains its separate recipient meaning: relinquish grants issued **to** your account. Already admitted commands can continue. Upgrading invalidates existing grants.
