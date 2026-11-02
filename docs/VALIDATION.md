# Validation — agent-sudo 1.0.2

Version 1.0.2 expands frontend help and adds `-h`; authorization behavior is unchanged. The 1.0.1 evidence below describes the preceding release, not the 1.0.2 binaries. See publication records for 1.0.2 checks. Loom smoke-tested 0.2.0 and a later token; the earlier grant was denied after its stated expiry, although the denial did not distinguish expiry from revocation.

# Validation — agent-sudo 1.0.1

Date: 2026-11-02. Release 1.0.1. Loom 0.2.0 root-command smoke passed; user-requested expiry recheck pending. This 1.0.1 build is tested in disposable VMs. Privileged work occurs only in the two disposable QEMU/KVM VMs, with no host mounts, development-host installation or Loom changes. Public delivery is through SH Website; no GitHub push/release.

## Exact tested systems

| VM | OS | Kernel | Active sudo | Package | visudo |
|---|---|---|---|---|---|
| noble | Ubuntu 24.04.5 LTS amd64 | 6.8.0-147-generic | traditional sudo 1.9.15p5 | 1.9.15p5-3ubuntu5.24.04.4 | 1.9.15p5, grammar 50 |
| resolute | Ubuntu 26.04.1 LTS amd64 | 7.0.0-38-generic | sudo-rs 0.2.13 | 0.2.13-0ubuntu1.2 | visudo-rs 0.2.13 |

Systemd: 255.4-1ubuntu8.18 / 259.5-0ubuntu3.4 respectively. Cloud image SHA-256: noble `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`; resolute `5645d0318ad21f643ebb1ac4567514620e9893380b07b0201fda163baa5b7eb5`, verified against Ubuntu's downloaded SHA256SUMS before boot. Ubuntu 26.04 also contains traditional sudo 1.9.17p2, which was **not** the active/tested backend and is not in the supported preview allowlist.

## Exact production binaries

```
agent-sudo        66920b0f70eacf2cc738de273d603b0a20594bc8a2a47ffd8cca75aa31acca85
agent-sudo-helper 1bf7b252527b7cd551f2b55ac0f4ea2d405a79af4c24dd071ba5c44187977e9e
```

Both binaries reproduced identically from a relocated source directory and independent Cargo target, using locked offline dependencies and Rust 1.97.1/musl. Package construction enforces these hashes. The package archive checksum is recorded alongside the package rather than inside its own contents.

## Installed-binary acceptance

| Suite | Ubuntu 24.04.5 / sudo 1.9.15p5 | Ubuntu 26.04.1 / sudo-rs 0.2.13 |
|---|---:|---:|
| Core | 64 pass | 64 pass |
| Extended | 24 pass | 24 pass |
| Dynamic workflow / migration | 15 pass | 15 pass |
| Creator-scoped revocation | 11 pass | 11 pass |
| Real clock / expiry | 2 pass | 2 pass |
| Actual ACPI suspend | 1 pass | 1 pass |
| SSH / reboot / removal | 10 pass | 10 pass |

**254 checks passed on the exact production binaries**, 127 per VM. The dynamic suite was rerun after adding an independent unauthorized-administrator check using root-injected consistent sudo metadata; the table counts it once. Raw root injection is identified as a fixture, not an escalation by a non-root process.

Suites run sequentially per VM, concurrently across VMs. Runners discard old result files and compare installed hashes before/after extended, dynamic and lifecycle suites. SSH/suspend checks use those same installations. Early review builds and failed harness runs are excluded from final counts.

Core: strict hostile helper requests; malformed/duplicate/oversized JSON; exact argv; root context, descriptor closure and binary 4 MiB streams; token binding; safe state/link/ACL checks; pending caps and deadlines; fresh PAM; hidden input; interruption; revoke/admission and maintenance races; failed token delivery; mid-install rollback; traditional-sudo I/O log exemption with unrelated logging preserved; sudo-rs fail-closed unsupported logging.

Extended: separate result descriptor; binary/error framing; non-UTF-8 rejection; hidden input echo restoration; high descriptors; malicious stream frames; real cached-sudo access after policy removal still denied by the helper; record/list/global/denial bounds; stale helper; blocked metadata output versus revocation; early exit/disconnect; later logging overrides; two grants each requesting fresh PAM in the same TTY.

Dynamic: default username from the real UID despite spoofed USER/LOGNAME; Enter selects 10 minutes, validated from actual grant records; local expiry in America/New_York including zone/offset; readable terminal grant output; token-only redirected stdout; administrative revocation instruction; actual upgrade from 0.2.0 invalidating old grants; positional grant; username-only duration prompt with PAM; bare prompts (core); invalid/root/missing recipients; new local accounts without installation; another administrator under independent NOPASSWD policy; non-admin administrative dispatch denial; simultaneous recipients preserving each other's grants; observed account deletion and cleanup; no-grant readiness denial; pending caps before lock waiting; actual published 0.1.0 install/upgrade with old token and waiting-old-helper denial; partial schema mismatch.

Lifecycle: real one-minute expiry with cleanup stopped, newly issued grants leaving old deadlines unchanged, admitted 65-second root work surviving expiry, actual wall-clock movement forward/back, actual ACPI S3 suspend and wakeup, actual SSH token delivery, reboot/boot binding and cross-host rejection. Removal preserves unrelated sudo and the separate ops/grant-agent-sudo.sh fixture, disables timer/removes managed state, and retains the disabled stable-lock tombstone.

## Native/build checks

Seven Rust tests, including 20,000 deterministic parser mutations; clippy with warnings denied; Rust 1.88 compatibility; shellcheck; Python compilation; Git whitespace checks. cargo audit: 1,402 advisories, 30 locked dependencies, no findings (2026-11-02). Musl emits libc's deprecated time_t alias notice; supported amd64 ABI remains 64-bit and UTC output is exercised in actual grants. This is bounded mutation testing, not an unlimited coverage-guided campaign.

## Public installation and page checks

The immutable release report records prepublication evidence. Public-URL installation, fault injection and live page checks are recorded separately in 1.0.1-PUBLIC_VALIDATION.md and sanitized docs/publication/1.0.1-* evidence after upload.

The literal command is `curl -fsSL https://tools.simplehelp.io/agent-sudo/install.sh | sh`. The bootstrap needs no recipient selection; sudo reads its normal password from the controlling terminal even while the script arrives through a pipe. Immutable 0.1.0, 0.2.0 and 1.0.0 public bytes are preserved.

## Real evidence versus injected faults

Actual VM installations, PAM/authentication cache, encrypted SSH, public HTTPS downloads, real elapsed expiry, wall-clock changes, ACPI suspension and reboot are integration evidence. Malformed protocol inputs, root-altered state/ACL/link fixtures, forced systemd rollback, wrong schema and record/count limits are deliberate faults. Public download/checksum/truncation failures use VM-local PATH shims, not a claimed live hosting outage. The test executes every proper byte prefix of the bootstrap under command-marker shims, with the full script as a positive control; no truncated prefix may begin installation. Package truncation/download/checksum faults must preserve installed binary/config/policy hashes and never invoke sudo.

No exhaustive power-cut recovery, independent audit, 1.0.1 production/Loom deployment, other CPU architectures or other sudo versions/policies are claimed. Name/UID/GID reuse between checks cannot be detected; revoke before account reuse. See SECURITY_REVIEW.md and OPERATOR.md for trust limits. Raw logs and VM fixtures remain ignored locally; only sanitized results/hashes are in docs/publication/.

Creator-scoped suite: issuer versus recipient scope across three recipients; preserves other creators including grants to the issuer; fresh password prompt even with cached sudo; no self-grant required; zero-match success; root issuer scope; nonadministrator sudo and independently checked helper denial; injected selection/extra-field/schema rejection; existing recipient --all behavior; expired stored record cleanup (root-injected deadline fixture); lock ordering versus new issuance; concurrent batches; maintenance generation changes; independently restricted grant-only sudo policy cannot authorize bulk revocation. Dynamic suite adds actual published 1.0.0 installation and upgrade with old-token invalidation and the new command. The initial targeted run exposed a test-only module-name shadowing error, fixed before all final evidence was collected.
