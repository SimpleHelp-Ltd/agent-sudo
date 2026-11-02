# Implementation security review — 1.0.0

Reviewed locally on 2026-11-02. This is an implementation review and adversarial testing by the implementer, **not an independent audit**. Privileged testing is limited to disposable VMs; public release assets/page are authorized through SH Website. No Loom/development-host installation during this release task, GitHub push or GitHub release.

## Scope and conclusion

Reviewed frontend parsing/prompts/descriptors, privileged operation dispatch, sudo transport and policy, administrative issuance authority, token generation/verifiers, state files/ACLs, boot/clock expiration, admission/revocation/maintenance ordering, root process context, framed streams/signals, cleanup, installation/rollback/removal and build/test infrastructure. The prototype transport gate preceded frontend implementation. Actual traditional sudo and sudo-rs VM evidence is in VALIDATION.md.

The trust boundary is explicit: a local account can launch four narrow token operations, with a live grant required before READY; it cannot mint a grant through those operations. Requests never select the helper operation. Every operation independently checks effective root identity, consistent sudo actor metadata, installed helper inode, enabled root-owned configuration, current live identity-bound grant where applicable, and sealed supported sudo policy. A run then checks the random secret verifier, actor UID/GID/name, current account mapping, host, boot, generation and exact BOOTTIME deadline while locked.

A grant intentionally permits arbitrary root code. Once admitted, root can alter this installation, credentials or the host and retain authority. Expiry/revocation is an admission rule, not containment or termination. Existing sudo policy is independent.

## Findings repaired during development

- Authorization cannot rely on `sudo -n`: independent config/policy checks deny missing/disabled grant state or removed policy even when an ordinary administrator's real sudo cache still launches the helper.
- Stable persistent lock and installation generations serialize issuance/revoke/admission/cleanup with maintenance. Stale helpers compare their executing inode to the installed helper; missing/disabled stores never regenerate grants. Removal retains a disabled lock tombstone.
- Arbitrary command bytes and child exit 125 cannot serve as tool protocol markers. Versioned response frames and a separate frontend result descriptor distinguish binary output, signals, child status and tool errors. Mixed-stderr JSON is documented as a convenience only.
- Waiting for input or blocked metadata output while holding the maintenance lock could delay revocation. Header reads occur without that lock; control writes occur after releasing it, have deadlines, and retain admission slots. Failure output and denial-log locking do not block after slot release. An actual 4096-byte stalled status pipe regression verifies concurrent revocation.
- A blanket sudo logging exemption is insufficient if later command-specific defaults/tags override it. The supported policy model rejects external command-scoped Defaults, recording tags, continuations, custom plugins, external includes and remote/subcommand recorders. Policy/binary hashes are checked before token transmission and again on admission. Global traditional-sudo recording remains supported with a narrow helper exemption; unrelated recording is verified to continue.
- Sudo-rs 0.2.13 rejects traditional I/O logging options. It receives a separately tested `!use_pty` rule; unsupported recording settings fail activation instead of being ignored.
- Grant delivery is not transactionally exactly once. A receipt after frontend output flush lets the helper revoke detectable failures/missing receipts. Locks are released while awaiting receipt. Crash after receipt can leave a grant live and is documented.
- Tokens and request buffers now zeroize on drop/error paths where practical; raw secrets are absent from argv/environment, logs and persistent state. Core dumps are disabled. No secrecy claim against root capture or swap.
- Safe state access verifies every parent and uses retained directory descriptors for record creation/removal and lock/slot/denial files. Symlinks, multiple links, wrong owners/modes, extended ACLs and unsafe parents fail closed. Invalid/corrupt records do not become authorization.
- Output timeout originally risked discarding buffered data after child exit when a reader stalled. Only idle inherited pipes now time out; buffered output drains correctly. Actual delayed-reader regression passes.
- Frontend stdin read failure could leave the child waiting. It now closes command input logically and reports tool failure even if the program exits zero.
- Reaping a leader before all process-group signaling ended could permit PID reuse. `waitid(WNOWAIT)` keeps the leader unreaped until forwarding stops; interruption during spawn is recorded and forwarded. Child execution resets signal handlers.
- Child setup clears all UID/GID variants and supplementary groups, environment, cwd, umask and unintended descriptors. `close_range(CLOEXEC)` retains Rust's exec-error pipe until exec without leaking it into the program.
- Rollback also restores its managed-file manifest; upgrades always invalidate grants. Managed paths and manifest shape are validated, modified/unmanaged files refused, obsolete pending slots pruned, and state/config/protocol/denial workloads bounded.
- Test infrastructure fixes prevent stale evidence reuse, enforce exact tested binary hashes, distinguish clock/record injection from real clock tests, and support the two actual PAM prompt formats without echoing fixture passwords.

## 0.2 dynamic issuance review

- Machine-wide install accepts no recipient list. Only independently authorized administrative `grant` can create a grant, which itself represents recipient registration. The managed ALL rule names only exact run/status/revoke/revoke-all helper arguments; JSON cannot alter dispatch. Each administrative request independently checks the actor's existing sudo authorization for that exact operation. Normal frontend issuance uses fresh `sudo -k` authentication; existing NOPASSWD policy remains authoritative.
- Recipient gates require current live UID/GID/name/host/boot/generation/deadline binding before READY, then validate the specific secret again at admission. An unregistered caller receives no READY. All callers acquire bounded slots before waiting for the maintenance lock, preventing unauthenticated local callers from accumulating lock waiters.
- Issuance uses the stable lock without modifying policy/config/generation, preserving unrelated recipients and grants. At most 128 grants represent registrations; expiry/revocation/deletion removes eligibility. UID slots now use a fixed 128-bucket namespace, avoiding persistent growth across account churn.
- Schema 2 activates only after disabling/invalidation/replacement/validation. Old schema and copied/stale helpers fail closed. An actual 0.1.0 package upgrade tests old-token and waiting-old-helper denial; root-injected partial schema tests are separately identified.
- Moving admission slots before lock acquisition bounds unregistered local waiters; a real flock contention test verifies that excess callers fail before READY. A concurrent revoke may be rejected by that bound and must retry before its successful ordering point.
- The entire hosted bootstrap is one compound command whose closing brace is the final byte, preventing any proper truncated prefix from invoking installation. All proper byte prefixes are tested with syscall-command marker shims; public successful installation separately exercises actual HTTPS, sudo and installed binaries.

## Remaining limits and untested scope

- Supported platforms remain deliberately narrow: Ubuntu amd64/systemd, traditional sudo 1.9.15p5 and sudo-rs 0.2.13 release families. Arbitrary sudo plugins, central policy, command-scoped custom Defaults and other versions are not validated; installation fails closed rather than modifying unrelated policy.
- No guarantee of secrecy from a compromised root, existing host tracing/audit/eBPF/terminal recording, same-UID process inspection, swap or malicious authorized root code. Static musl account lookup is for local accounts, not general NSS/LDAP integration.
- Same-name/same-UID/GID account recreation is not reliably detectable; revoke before changing accounts. Machine-id clones are not an independent hardware identity; boot binding and volatile records add separate checks.
- A killed/crashed frontend after acknowledgment may leave a live grant. Lost secrets cannot be recovered; list/revoke or reboot. Revocation/deletion is not secure erasure.
- No PTY/editor/GUI support; non-UTF-8 argv is rejected. Background root descendants can continue, and continuously writing descendants can keep streams active. Disconnect termination is best effort, not a sandbox.
- Pending helpers, records, listings and control deadlines are bounded, but launching sudo, OS process limits and authorized root workloads are not a complete availability defense.
- Rollback is tested with a real post-replacement systemd failure, not power loss at every filesystem instruction. Multi-file installation is not a filesystem-wide atomic transaction; interruption may require the independent recovery procedure. Repeated rollback I/O failure itself cannot be guaranteed recoverable automatically.
- Parser mutation fuzzing is bounded deterministic mutation testing, not an unlimited coverage-guided campaign. Privileged state/identity/deadline fixtures are identified separately from actual PAM, clock, reboot, SSH and suspend evidence. Hardware/platform combinations outside the recorded VMs remain untested.

## References

Policy assumptions are checked against the installed VM tools and [sudo's primary manual](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in), especially command matching, Defaults ordering and I/O tags. [sudo-rs upstream](https://github.com/trifectatechfoundation/sudo-rs) documents the Ubuntu 26.04 base as 0.2.13. Expiry uses [Linux CLOCK_BOOTTIME](https://man7.org/linux/man-pages/man2/clock_gettime.2.html), including time spent suspended. These sources explain the design; actual compatibility evidence is the VM test record.

## 1.0 presentation review

Changed only the frontend UI/defaults and package version. Real-UID lookup prevents USER/LOGNAME from selecting a misleading default recipient; helper identity/duration checks remain authoritative. Displayed local expiry is advisory: admission continues to use boot-relative deadlines. Generic denial guidance deliberately avoids claiming an exact expiry/revocation cause, or exposing token/state diagnostics. Redirected token output, secret wiping and delivery acknowledgment ordering remain intact. Loom's 0.2.0 root `/usr/bin/id` smoke test succeeded on 2026-11-02; the user-requested expiry recheck remains pending. 1.0 is validated in disposable VMs; it has not been installed on Loom by this release task. No independent security audit is claimed.
