# Changelog

## Unreleased — 2026-11-16

- Refresh the README with prominent SimpleHelp guide/download links, an administrator/recipient quick start, current-release distinctions and local build instructions; correct stale operator archive examples and generalise private operational references.

- Retire the old tools-host information page with a verified minimal forwarding page so existing handoff URLs reach the new guide.
- Point terminal handoffs, CLI help and current documentation to https://simple-help.com/tools/agent-sudo; keep installers and versioned downloads on tools.simplehelp.io. Existing 1.0.3 binaries remain unchanged until a new release.

- Applied Apache-2.0 to the current original source/documentation with SimpleHelp attribution, source licence headers, and licence/attribution/dependency notices in future release archives; existing releases remain unchanged.
- Reviewed reachable Git history, tracked files and public release inputs; detailed review records remain local.

## Website — 2026-11-04

- Redesigned `website/agent-sudo.html` for readability: administrator/agent entry choices, numbered steps, command tables, a prominent root-access warning and collapsible secondary details. Same install command, copy behavior, downloads, hash and SimpleHelp styling; local and live browser checks pass. Published to tools.simplehelp.io on 2026-11-04 (receipt `docs/publication/1.0.3-page-redesign-receipt.json`).

## 1.0.3 — 2026-11-04

- Terminal grant output says `Copy and paste this line to your agent:` followed by `see: https://tools.simplehelp.io/agent-sudo.html | TOKEN`. Redirected stdout remains token-only.
- Issue compact 67-character v2 Base64url tokens, preserving 128-bit grant IDs, 256-bit secrets and all authorization checks. Accept existing v1 tokens with the same verifier; installation still invalidates prior grants.
- Passed 230 installed-binary VM checks, eight native/parser tests, lint/MSRV/dependency checks and identical relocated-source reproduction. Publish reviewed user-facing documentation with internal publication history excluded from new archives; clear generated staging contents before packaging to prevent stale files.
- Update the optional SSH/reboot harness to decode v2 grant IDs. This test-only follow-up is later than the frozen release source snapshot.
- Published the immutable release, pinned installer and page through SH Website. Passed 38 actual public installation checks plus live browser/clipboard/layout/download verification; earlier versioned assets remain unchanged.

## 1.0.2 — 2026-11-03

- Expand command-line help with agent and administrator instructions, safe token input, examples and automation options; add the `-h` shortcut. Passed 128 core VM checks and installed help checks. The public installer selects 1.0.2; public installation checks passed in both Ubuntu VMs. See docs/PUBLISHING.md.

## 1.0.1 — 2026-11-02

- Add `agent-sudo revoke all` to revoke grants issued by the calling administrator across all recipients, with fresh sudo authorization and a readable count. Preserve other administrators’ grants and existing recipient `revoke --all` behavior.
- Serialize batch revocation against issuance, admission and maintenance; retain per-grant auditing and bounded parsing.
- Passed 254 installed-binary VM checks, 38 actual public installation checks, seven native/parser tests, lint/MSRV/dependency checks and identical relocated-source reproduction. Truncated downloads preserve installations. Publication evidence is recorded under docs/publication/1.0.1-*.

## 1.0.0 — 2026-11-02

- Default prompted username to the calling account and duration to 10 minutes.
- Replace dense grant output with readable account, local expiry/timezone, private token and administrative revocation instructions. Preserve token-only stdout when redirected.
- Clarify hidden token input and actionable access-denial messages; keep authorization and grant lifetime rules unchanged.
- Release validation and tools.simplehelp.io publication recorded in docs/publication/1.0.0-*; previous versioned assets remain immutable.
- Passed 230 installed-binary VM checks, 36 public installation checks, native/parser tests, lint/MSRV/dependency checks and identical relocated-source reproduction. Public failures/truncation preserve existing installations.


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
- Documented immutable release publication ordering and public VM bootstrap validation; No production-host installation or GitHub release was performed.
- Verified all eight public downloads and exact hashes; 30 public bootstrap/installation/grant/removal VM checks passed across both supported sudo implementations.
- Published the responsive HTML page through SH Website and verified live HTML MIME/rendering, desktop/tablet/mobile layouts, real clipboard copying and denied-copy fallback; recorded checksum-guarded metadata update and sanitized publication receipts.

## Short public installation command draft — 2026-11-02

- Simplified the page, copy button, command file and documentation to `curl -fsSL https://tools.simplehelp.io/agent-sudo/install.sh | sh`.
- Guarded bootstrap execution with a complete shell compound command so a truncated script cannot begin installation. The initial recipient-prompt draft was superseded by the 0.2.0 machine-wide workflow before publication.
- Kept 0.1.0 immutable while preparing the new preview; download verification, temporary files and cleanup stay inside the bootstrap.

## 0.2.0 — 2026-11-02

- Machine-wide installation without recipient selection; positional and prompted administrative grants dynamically authorize existing non-root recipients.
- Preserve private tokens, exact recipient-only sudo dispatch, independent administrative policy checks, bounded state, maintenance invalidation and separate binary streams.
- Simplify public installation to a piped hosted bootstrap guarded against truncated scripts; separate administrator and agent guides, using inspected SimpleHelp styles.
- Bound helper slots before maintenance-lock waiting; verified 222 installed-binary VM checks, native/parser tests, clean dependency audit, and identical relocated builds.
- Verified seven immutable public downloads and 36 actual public-command VM checks; the 2,598 proper prefixes of the final hosted script cannot begin installation. Fault cases are identified as VM-local injections.
- Published the guarded installer and SimpleHelp guide; live browser, keyboard, clipboard, 13 URL/MIME/hash checks and unchanged 0.1.0 archives verified. Saved sanitized receipts and stopped the test VMs.
