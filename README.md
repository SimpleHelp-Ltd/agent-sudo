# agent-sudo

**[agent-sudo guide and downloads](https://simple-help.com/tools/agent-sudo)** · [All SimpleHelp tools](https://simple-help.com/tools)

A local Linux tool for a human administrator to delegate **temporary arbitrary root commands** to an authorized account, without sharing an administrator password.

**Current published release: 1.0.3.** Its installed binaries were validated in disposable Ubuntu VMs. This checkout includes unreleased Apache licensing and guide-link changes; the public installer still installs the original MIT-licensed 1.0.3.

```sh
curl -fsSL https://tools.simplehelp.io/agent-sudo/install.sh | sh
```

[Public download and installation guide](https://simple-help.com/tools/agent-sudo). The bootstrap installs machine-wide and verifies the pinned package before normal sudo installation. Select the recipient later when issuing a grant. [Website publication workflow](docs/PUBLISHING.md). Separate Rust frontend and privileged helper; tested in disposable Ubuntu VMs. See [validation](docs/VALIDATION.md), [security review](docs/SECURITY_REVIEW.md), [operator guide](docs/OPERATOR.md) and [wire/security design](docs/DESIGN.md).

## Quick start

After installation, a sudo administrator grants access to an existing non-root account:

```sh
agent-sudo agent 10
```

Send the printed handoff privately to the recipient. As that recipient:

```sh
agent-sudo run -- /usr/bin/id </dev/null
agent-sudo status
```

Enter the token at the hidden prompt. The recipient does not need existing sudo privileges or the administrator's password. To revoke every grant issued by the administrator, run as that administrator:

```sh
agent-sudo revoke all
```

**Grants permit full root access.** Expiry and revocation block new commands; already admitted root work can continue. Upgrading invalidates existing grants.

## Commands

Run `agent-sudo --help` (or `agent-sudo -h`) for an agent-oriented guide available directly in the terminal.

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
agent-sudo --help | -h | --version
```

Redirected grant stdout contains only one token line; a readable account, local expiry/timezone and administrator revocation command go to stderr. Terminal output from this checkout says `Copy and paste this line to your agent:` followed by `see: https://simple-help.com/tools/agent-sudo | TOKEN` with the actual private token. Published 1.0.3 prints the old tools-host URL, which forwards to the new guide. New tokens are 67-character v2 Base64url strings, retaining a 128-bit grant ID and 256-bit secret; v1 tokens are also accepted. The token stays separate from the URL. Detailed machine identity stays in status metadata. Status/list output is JSON metadata without tokens/verifiers. `--key-fd` consumes a token line from a descriptor >=3. Tokens in argv/environment and automatic token files are unsupported. Commands receive binary stdin/stdout/stderr and their actual exit status (signals map to 128+signal). For reliable automation, supply a separate writable `--result-fd`: it receives one JSON final result, distinguishing child code 125 from tool failure. `--json-result` is a convenience on stderr, which remains mixed with arbitrary child stderr; use the separate result descriptor for unambiguous results.

This is **delegated root authority**, not a sandbox. Tokens are bound to a local account, host and boot. Expiry/revocation/reboot stop future admissions. Already admitted processes survive expiry/revocation, and root can establish persistence. Processes sharing a Linux UID are not strongly isolated. Preserve an independent administrator session. No listener, setuid application, daemon command server, saved administrator password or change to unrelated sudo permissions.

Supported platforms: Linux amd64, Ubuntu 24.04/26.04 with systemd; traditional sudo 1.9.15p5 or sudo-rs 0.2.13. Policies outside the validated local-file model fail closed. Any sealed sudo-policy change requires administrator reinstallation/revalidation and invalidates all tokens. [Build and reproduce artifacts](docs/BUILD.md). Not an independent security audit.

`agent-sudo revoke all` requests fresh sudo authorization and revokes every stored grant whose creator UID matches the calling account, across all recipients. It works even if you have no grant yourself and succeeds if there are no matching grants. Grants issued by other administrators remain valid, including those issued to you. Use it without a leading `sudo` to retain your own issuer identity; `sudo agent-sudo revoke all` selects root-issued grants. Creator identity uses the recorded numeric UID; revoke before reusing administrator UIDs. The existing `agent-sudo revoke --all` retains its separate recipient meaning: relinquish grants issued **to** your account. Already admitted commands can continue. Upgrading invalidates existing grants.

## Build from source

Requires the Rust toolchain, musl-tools and Python 3. The build creates local artifacts without installing or publishing them:

```sh
python3 scripts/build-release.py
```

See [build and VM validation](docs/BUILD.md) for toolchain versions, reproducibility and testing. Select a new version before distributing a changed binary.

## Licence

Copyright 2026 SimpleHelp. The original code and documentation in this checkout
are licensed under the [Apache License, Version 2.0](LICENSE). Attribution is in
[NOTICE](NOTICE). [Third-party notices](THIRD_PARTY_NOTICES.txt) preserve dependency
licences; update them when dependencies or build toolchains change.

Previously published releases, including 1.0.3, retain their original MIT licence.
This change applies to the current source and future releases; it does not alter
existing release archives or withdraw permissions already granted.
