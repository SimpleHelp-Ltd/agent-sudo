# agent-sudo: temporary token-authorized administrator commands

Historical input: installation-time enrollment described below was superseded by the authorized 0.2 machine-wide/dynamic-grant workflow in DESIGN.md and OPERATOR.md.

Status: development specification; this request does not install software or change privileges on any host.
Date: 2026-11-02. Initial target: Ubuntu Linux with systemd, traditional sudo or sudo-rs.

## 1. Intended outcome

Build a small command-line app that lets a human administrator issue a temporary access token to an agent. The agent can then run commands as root on that host using the token, without receiving, storing or replaying the administrator's password.

The administrator runs `agent-sudo` with no arguments, authenticates through normal sudo, chooses a recipient account and duration, and receives a token once. The agent uses the same app to submit commands. Every invocation checks the token, recipient and expiry before execution.

There is no network listener, persistent command server, encrypted password file, setuid app or passwordless sudo permission for arbitrary commands. Elevation uses the existing sudo installation and a narrowly authorized, root-owned helper executable. That helper is security-critical privileged code even though it is short-lived.

Preserve unrelated administrative tools and existing sudo policy. Do not silently replace, enable or depend on a separate account-wide passwordless sudo mechanism.

## 2. Scope and trust model

- Tokens permit arbitrary commands as root, including an explicitly requested shell. This is delegation to a trusted operator, not a sandbox or a command allowlist.
- A token is bound to a local numeric UID, the corresponding account identity, the issuing host and its current boot. It is reusable until expiry or revocation.
- Possession of the token plus access to its enrolled account authorizes use. A token alone must not authorize a different UID or another host.
- Other processes running as the same Linux user can potentially inspect that user's processes and token input. Do not claim isolation between SSH sessions sharing a UID or that the token uniquely identifies a particular AI agent. A dedicated agent account is an optional operational improvement.
- Revocation and expiry stop future authorization. They do not terminate previously authorized commands, root shells, descendants or background jobs. Root access can alter the helper, create another credential or otherwise retain access.
- Existing sudo permissions and authentication caches are independent. An account may retain administrator access through them after a token expires. This tool must not weaken or erase existing policy.
- Protect against an unprivileged caller trying to bypass token validation, forge identity, exploit malformed input, manipulate state files or obtain secrets from routine logs. Host-root compromise and a deliberately malicious authorized root operator are outside the protection offered.

## 3. Public command interface

The following is the target interface, not a statement that these commands exist today.

| Invocation | Required behavior |
| --- | --- |
| `agent-sudo` | Interactive grant creation using normal administrator authentication. |
| `agent-sudo grant --user simplehelp --minutes 60` | Explicit equivalent; still requires normal administrator authorization. |
| `agent-sudo run -- /usr/bin/id` | Read a token with terminal echo disabled, then execute the argument vector as root. |
| `agent-sudo run --key-fd 3 -- /usr/bin/id` | Read the token from an already-open descriptor for noninteractive agent use. |
| `agent-sudo status` | Show the caller's grant metadata, never a token or verifier. |
| `agent-sudo revoke <grant-id>` | Revoke a grant belonging to the caller; no token is needed to remove one's own access. |
| `agent-sudo revoke --all` | Revoke all grants belonging to the caller. |
| `agent-sudo admin list` | Normal administrator authentication; list all grants without secrets. |
| `agent-sudo admin revoke <grant-id>` | Normal administrator authentication; revoke another user's grant. |
| `agent-sudo --help` / `--version` | Work without elevation. |

For no-argument issuance:

1. Explain that the token grants arbitrary root commands and that existing root processes outlive expiry.
2. Prompt for an existing recipient username, defaulting to the invoking account, and whole minutes, defaulting to 60. Accept 1–1440 minutes; reject invalid input without granting anything.
3. Authenticate using sudo's normal terminal/PAM path. The app must not implement a password prompt itself, use `sudo -S`, capture the password or save it. Request fresh authentication rather than intentionally relying on a timestamp cache; verify the installed sudo's semantics. If host policy already permits passwordless administration, report that a password challenge may not occur.
4. Print the token exactly once, alongside a nonsecret grant ID, host, recipient, expiry in UTC and early-revocation command. Distinguish token output from diagnostics. If delivery fails after creation, revoke the new grant.

The suggested `agent-sudo <access-key> command args` syntax is deliberately replaced in the MVP by a hidden prompt or `--key-fd`. Tokens in argv can appear in process listings, shell history and sudo command logs. Do not add positional tokens, token environment variables or automatic plaintext token files. Token input must remain separate from the requested command's stdin.

The automation guide must show a tested way to deliver a token over SSH without placing it in either local or remote argv, environment, history, traced shell output or a temporary plaintext file. Do not assume that passing descriptor 3 to the frontend means sudo preserves descriptor 3 for the root helper.

MVP command execution supports noninteractive programs, binary stdin/stdout, stderr, exit status and interruption. Full terminal emulation, interactive editors, SSH session termination, GUI support, command allowlists and remote grant management are out of scope. Reject unsupported terminal modes clearly.

## 4. Architecture and privilege boundary

Prefer a memory-safe compiled implementation, such as Rust, with a small dependency set and a lockfile. Keep the privileged helper small and reviewable. Do not implement the helper as a root shell script or load code/configuration from a caller-writable directory.

| Component | Privilege and responsibility |
| --- | --- |
| `/usr/local/bin/agent-sudo` | Ordinary user frontend: prompts, parsing and streaming transport. Not trusted to authorize anything. |
| `/usr/local/libexec/agent-sudo-helper` | Root-owned compiled helper, launched by sudo for one operation. Independently validates identity, protocol and state. |
| `/etc/sudoers.d/agent-sudo` | Managed narrow enrollment policy; only designated local users may invoke token operations without a password. |
| `/run/agent-sudo/` | Root-owned `0700` directory containing grants and locking state; records `0600`. Volatile state intentionally invalidates grants on reboot. |
| systemd cleanup timer | Periodically deletes expired grant records; cannot execute caller-supplied commands. Correct authorization does not depend on it running. |

All executable files and parent directories must be owned by root and unwritable by enrolled users, including through group permissions or ACLs. Helper mode `0755`, no setuid bit; sudoers mode `0440`. Disable core dumps for the frontend/helper while holding tokens and minimize secret lifetime in memory. Do not claim complete protection from swap, privileged debugging or host capture systems.

### Sudo integration

- Install/enroll only explicitly selected existing accounts. Enrollment allows contacting the helper; enrollment alone grants no root command execution. Keep the enrollment list in root-owned configuration; grant creation must reject a recipient who is not enrolled, rather than silently changing sudoers.
- Passwordless entries permit only exact helper operations `run`, `status`, `revoke` and `revoke-all`, with no additional OS-level arguments. Command data and grant IDs travel inside the bounded protocol. No wildcard command paths or argument patterns, `SETENV`, broad `NOPASSWD: ALL` or blanket group enrollment.
- Grant creation and administrative list/revoke use separate helper operations and the caller's existing administrator policy, with normal authentication. Do not make these passwordless through the tool's enrollment rule. Do not give an otherwise non-administrator the right to mint grants.
- A nonprivileged user invoking the helper directly must fail before touching protected state. For sudo entry, derive the original actor from validated sudo-provided identity, never a username/UID in the request. Reject missing or inconsistent metadata. Direct UID-0 invocation is an explicit administrative path, not an opportunity to trust arbitrary request identity.
- `run` always uses noninteractive sudo for the exact permitted operation. It must fail without prompting if the enrollment rule is absent; a token must not become a sudo password. Do not fall back to another elevation method.
- Strictly dispatch on helper OS arguments. A request to `run` cannot select `grant`, maintenance or an administrative operation through a JSON field or malformed argument vector.
- Validate generated policy with the host's actual `visudo`; then verify effective behavior, including overlapping rules, sudoers-rs configuration and negative cases. Parse success alone is insufficient.
- Inspect effective sudo I/O logging: request input contains the token, and grant output contains the newly issued token. Neither may be captured in sudo I/O logs. Where needed, use tested narrowly scoped logging settings for these helper operations, preserving normal authentication/event logs. If the installed sudo or site policy cannot satisfy this requirement, fail installation/enrollment with an explanation; do not silently leak tokens or disable system-wide auditing.

Traditional sudo and sudo-rs have different capabilities. The validated sudo-rs version is 0.2.13; recheck compatibility at development/test time. Do not depend on `NOTAFTER`, newer sudoers regex features, preserved extra descriptors or any other unverified feature.

### Request transport

Specify and version a small protocol before coding it. A suitable design is a length-prefixed bounded JSON header on the sudo helper's stdin, followed by the requested command's raw stdin bytes. The frontend consumes the key descriptor, constructs the header and forwards the remaining command input.

- Maximum header: 64 KiB, with a short bounded read deadline, maximum nesting and argument count; reject oversized, truncated, duplicate, unknown or incorrectly typed fields and embedded NULs.
- Read exactly the header length without buffering away command input. Close the original key descriptor after reading it. Never inherit a token descriptor into the requested command.
- The privileged helper treats every field as hostile. It never invokes a shell to interpret the header, uses `eval`, or interpolates a token into a subprocess command line.
- Preserve arbitrary binary command input, stream output without accumulating it in memory, and handle backpressure, early EOF, broken pipes and interruption. Test sudo's PTY settings; do not assume byte-transparent transport.
- A malicious enrolled user may contact the helper directly through sudo. Frontend checks are convenience only; security checks live in the helper.

## 5. Token and state lifecycle

1. Generate at least 256 bits of random secret using the OS CSPRNG. Use a versioned, URL-safe token containing a separate random nonsecret grant ID and secret. Limit accepted token lengths and reject malformed encodings.
2. Store only a verifier, such as SHA-256 over a domain-separated grant ID and random secret. Use a constant-time verifier comparison. A password KDF is unnecessary for a full-entropy random token; never substitute a human-chosen password.
3. Record a schema version, grant ID, creator UID, recipient UID and username, host/boot identity, creation UTC time, display expiry UTC time and an authoritative elapsed-time deadline. Expose no verifier through status or logs.
4. Bind expiry to Linux `CLOCK_BOOTTIME` so suspension counts and wall-clock adjustments cannot extend a grant. Check boot identity on every use; reboot invalidates all grants. State belongs in `/run`, not persistent backup storage. Reject missing/malformed state, wrong boot, inconsistent identity or unsupported schema.
5. Atomically create a grant with exclusive creation, root-only permissions and unpredictable file names derived only from validated nonsecret IDs. Use directory-relative safe opens, no symlink following, and validate ownership, type, permissions and link count. Reject hostile preexisting paths. Never build a file path from unrestricted user input.
6. Validate the token, actor, recipient/account mapping and deadline on every run. At the exact deadline, deny. Multiple grants are independent; creating another grant must not extend an existing token. Reject UID/name mismatches; document that same-name/same-UID account recreation is not reliably detectable and requires revoking grants before account changes.
7. Serialize authorization and revocation with a defined locking protocol. Immediately before admitting execution, recheck state and expiry under that protocol. Define that admission as the ordering point: a command already admitted before revoke/expiry may start or continue afterward; every admission ordered after revoke/expiry fails. Do not hold a grant lock for the full command lifetime.
8. Revocation removes the record and is idempotent. An enrolled account may revoke only its own grants. Administrative operations may revoke any grant after normal authorization.
9. Cleanup deletes expired or previous-boot records without following links. Stop the cleanup timer in tests to prove expiry still denies access. Deleting a verifier is cleanup, not secure erasure or a promise that an authorized root operator cannot retain access.

Do not persist raw tokens, passwords or reversible credentials. Do not store tokens in audit events, crash reports, diagnostic dumps or analytics.

## 6. Root command execution

- Require an absolute executable path and pass a real argument vector directly to `execve` or an equivalent API. Do not split strings or perform shell expansion. If a shell is needed, the caller explicitly requests an absolute shell executable and its arguments.
- Execute with root real/effective UID and GID, clearing supplementary groups inherited from the caller. Use working directory `/root` and umask `077`. No run-as-other-user, caller-selected environment or custom working directory in the MVP.
- Construct a minimal known environment, including root `HOME`, root identity and a fixed system `PATH`. Do not pass caller loader variables, language module paths, `SUDO_*`, token values or unreviewed environment entries into the command. Review locale handling and any sudo frontend requirements separately.
- Close state files, locks, token channels and every unintended descriptor before execution. Only the command's intended stdin/stdout/stderr remain.
- Do not modify the requested program's security semantics through an undocumented sandbox. The command intentionally receives root authority.
- Return the child's exit code and document signal handling. Reserve distinct tool error codes, with structured errors available for automation; child/tool code collisions must be distinguishable in that mode. Ensure failures after authorization do not report command success.
- Log grant creation, authorization/denial, revocation and cleanup using grant ID, actor UID, recipient UID, timestamps and executable path. Avoid command arguments and streams by default: they may contain application credentials. Never log the access token, verifier or password. Explain that external host tracing/auditing is outside the tool's complete control.

## 7. Installation, recovery and removal

Deliver source, reproducible build instructions, a versioned release artifact, checksums, an installer, an uninstaller and an operator guide. Include a short threat model and record exact tested OS/sudo versions. Do not describe the app as audited unless an actual independent audit has occurred.

The installer must require normal administrator authorization, check platform dependencies and system paths, detect conflicts with existing managed files, and validate policy before activation. Install the helper and root-only state infrastructure before enabling enrollment. Use atomic replacement and rollback on failure; leave unrelated sudoers entries, SSH configuration and other tools alone.

The helper must not run from the development checkout or load dependencies from it. A temporary missing grant store denies access; it must not cause automatic grant recreation. Upgrades invalidate existing grants rather than carrying them across a security-sensitive change.

Document an independent administrator recovery path: disable/remove this tool's enrollment policy first, validate sudoers, stop cleanup, remove grant state and managed binaries/configuration. Removal must invalidate tokens and preserve unrelated access. Keep an independent administrator session during initial installation tests. A token alone must never authorize install, enrollment changes, upgrades or grant creation through an accidental helper path; arbitrary explicitly authorized root commands can of course modify the host.

## 8. Required acceptance tests

Use disposable Ubuntu VMs for privileged integration tests. Mock-only tests and parser checks are insufficient. Do not install on a production or development host as part of testing without a separate deployment instruction.

| Area | Evidence required |
| --- | --- |
| Issuance | No-argument prompts; duration bounds; existing/unknown recipients; administrator success; unauthorized creation denied; no password handled by app; issuance failure leaves no grant. |
| Successful use | Token permits `/usr/bin/id` as UID/GID 0, exact argv including spaces/metacharacters, binary stdin, separate stdout/stderr, exit codes and interrupted/failed commands. |
| Token checks | Missing, malformed, modified, random, expired and revoked tokens fail; valid token under a different UID/host/boot fails; verifier never exposed. |
| Account semantics | Token works from a new SSH session for the enrolled UID; another session still needs the token; no claim of same-UID isolation; UID/name mismatch denies use. |
| Expiry | Exact deadline, suspend/resume, wall-clock movement, stopped cleanup and reboot all satisfy the specified semantics. New grants do not refresh old tokens. |
| Revocation/races | Own versus another user's revoke, administrator revoke, repeated revoke, simultaneous execution/revoke and cleanup races satisfy the documented admission ordering. |
| Privilege boundary | Direct unprivileged helper, forged actor data, alternate operations, extra helper argv, malicious protocol fields, missing enrollment and non-root helper execution all fail safely. |
| State integrity | Symlink/hardlink, path traversal, incorrect ownership/mode/ACL, directory substitution, truncated/corrupt state and concurrent creation attacks fail closed. |
| Secret handling | Exercise ordinary and I/O logging configurations. Inspect process argv/environment, shell history, journal, sudo logs, app errors and inherited child descriptors; no token/password appears except intentional issuance output and controlled token transport. |
| Process context | Verify root IDs/groups, `/root` cwd, umask, safe environment, no token/state descriptors and no implicit shell interpretation. |
| Compatibility | Real traditional sudo and real sudo-rs, using disposable equivalents of supported deployment versions; report exact versions and unsupported policy combinations. |
| Install/remove | Narrow policy effective with overlapping host rules; no cached-auth bypass of token validation; setup rollback, upgrade invalidation and clean removal; existing unrelated sudo rules unchanged. |
| Limits | Demonstrate that an admitted long-running command survives expiry and a future invocation fails; guide describes why full root access can retain access. |

Add parser fuzzing, dependency/security checks and focused tests for the privileged helper. Document review findings and unresolved risks before recommending deployment.

## 9. Development handoff

Implement the MVP described here. First inspect the target platform and produce the privilege/data-flow design, exact sudoers policy and protocol. Resolve transport and sudo logging compatibility in a disposable VM before building out the UI. Develop locally and test in disposable environments; deliver a reviewable build and test report. This handoff requests development, not production installation or a change to live sudo privileges.

The operator guide must explicitly state: no saved administrator password; tokens are bearer credentials bound to a Linux account; no strong separation among that account's processes; future commands stop at expiry/revocation/reboot; already admitted root work continues; full root can establish persistence.

## 10. Primary references

- [sudo project's sudoers manual source](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in): review command matching, argument matching, tags, environment and logging behavior against the installed version.
- [sudo-rs upstream source and compatibility documentation](https://github.com/trifectatechfoundation/sudo-rs): verify supported features and test the deployed version instead of assuming traditional sudo behavior.
- [Linux clock_gettime documentation](https://man7.org/linux/man-pages/man2/clock_gettime.2.html): implementation reference for boot-relative time including suspension; verify the target kernel APIs during development.
