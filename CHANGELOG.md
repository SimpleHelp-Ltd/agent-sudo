# Changelog

## 0.1.0 — 2026-11-02 (local development build)

### Added
- Initialized the agent-sudo repository with project documentation and local working-log exclusions.
- Recorded privilege/data flow, versioned framed protocol, exact draft policy, independent enrollment/policy gates, maintenance ordering, limits and crash-delivery semantics before implementation.
- Implemented bounded framed protocols, helper enrollment/policy gates, boot-bound verifier records, serialized maintenance, root command streaming, frontend CLI and private token input.
- Proved byte-transparent sudo transport in Ubuntu VMs with traditional sudo 1.9.15p5 and sudo-rs 0.2.13; used distinct policies for their logging capabilities.
- Added token-delivery acknowledgments, separate result descriptors, policy revalidation, private record integrity checks, serialized upgrades/removal, cleanup timer and offline installer.
- Added actual installed-VM acceptance tests, parser mutation tests, local artifact packaging and dependency auditing.
- Review fixes: keep exited child unreaped while group signaling is possible, restore installation manifest on rollback, reject unsupported sudo continuations/plugins/tags, and prune obsolete per-account slots.
- Fixed descendant-pipe timeout to drain buffered output correctly under slow-reader backpressure; added actual installed-helper delayed-reader regression.
- Reject external command-scoped sudo Defaults and recording tags that could override secret-safe transport; retain unrelated policy unchanged.
- Fixed frontend stdin-error handling, safe interrupted startup and strict installation-manifest validation.
- Prevented stalled control-output readers from holding the maintenance lock; bounded control writes and nonblocking denial handling.
- Used verified directory descriptors for grant creation/removal and lock/slot/denial state access.
- Completed 202 compiled-binary checks across actual Ubuntu 24.04.5/traditional sudo 1.9.15p5 and Ubuntu 26.04.1/sudo-rs 0.2.13 VMs, including ACPI suspend, PAM/cache, SSH, reboot and clean removal; four initial transport checks and native/parser/dependency checks also passed.
- Documented final security review, exact artifact hashes, reproducible relocated-source build, operator recovery and remaining limits. No push, publication or host installation.

## Public preview website — 2026-11-02

- Added tools.simplehelp.io preview page and HTTPS bootstrap using the exact VM-tested 0.1.0 package and pinned SHA-256.
- Require explicit existing recipient selection, preserve terminal sudo authentication, and verify downloads before invoking the offline installer.
- Documented immutable release publication ordering and public VM bootstrap validation; Loom and GitHub releases remain untouched.
- Verified all eight public downloads and exact hashes; 30 public bootstrap/installation/grant/removal VM checks passed across both supported sudo implementations.
- Published the responsive HTML page through SH Website and verified live HTML MIME/rendering, desktop/tablet/mobile layouts, real clipboard copying and denied-copy fallback; recorded checksum-guarded metadata update and sanitized publication receipts.

## Short public installation command — 2026-11-02

- Simplified the page, copy button, command file and documentation to `curl -fsSL https://tools.simplehelp.io/agent-sudo/install.sh | sh`.
- Guarded bootstrap execution with a complete shell compound command so a truncated script cannot begin installation; recipient selection remains on `/dev/tty`.
- Preserved the exact tested 0.1.0 package and pinned SHA-256; download verification, temporary files and cleanup stay inside the bootstrap.

## 0.2.0 — 2026-11-02

- Machine-wide installation without recipient selection; positional and prompted administrative grants dynamically authorize existing non-root recipients.
- Preserve private tokens, exact recipient-only sudo dispatch, independent administrative policy checks, bounded state, maintenance invalidation and separate binary streams.
- Simplify public installation to a piped hosted bootstrap guarded against truncated scripts; separate administrator and agent guides, using inspected SimpleHelp styles.
