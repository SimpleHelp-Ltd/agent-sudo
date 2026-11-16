# Validation — agent-sudo 1.0.4

Date: 2026-11-16. Release 1.0.4 adds Apache-2.0 licensing/notices and points help and terminal handoffs to the SimpleHelp guide; grant authorization and protocol behaviour are unchanged. Testing uses actual installed static binaries in disposable QEMU/KVM VMs, with no host filesystem mounts or development-host installation. This is implementer testing, not an independent audit.

## Exact tested binaries

```
agent-sudo        eb42dd5e1106f8d0ce8a7195ce3b54824734f2a047cad21af1f306de6c7156dc
agent-sudo-helper 2324ed667b554c7d2ac5d44a94051f686d4ae988737db0116efbc5154bb4f6b6
```

Both binaries reproduced byte-for-byte from a relocated source directory with an independent target directory, locked offline dependencies, Rust 1.97.1 and the x86_64-unknown-linux-musl target. Release packaging enforces these exact hashes. Archive hashes are recorded alongside the archives.

## Installed-binary checks

| Suite | Ubuntu 24.04.5 / sudo 1.9.15p5 | Ubuntu 26.04.1 / sudo-rs 0.2.13 |
|---|---:|---:|
| Core | 65 pass | 65 pass |
| Dynamic workflow / migration | 15 pass | 15 pass |
| Creator-scoped revocation | 11 pass | 11 pass |
| Extended | 24 pass | 24 pass |

230 checks passed against the exact binaries above. Suites run sequentially within each VM, concurrently across VMs; stored results verify installed binary hashes. The new integration case independently decodes v2 in Python, checks 67-character length and 48-byte payload, uses equivalent v1/v2 credentials against the same grant, rejects malformed inputs and wrong accounts, and proves revocation blocks both encodings. Terminal tests assert exactly one `see: https://simple-help.com/tools/agent-sudo | TOKEN` line after the copy/paste prompt. Redirected stdout remains exactly one token plus newline; expiry/account/revocation text stays on stderr.

Existing checks cover actual sudo authentication, strict helper parsing, binary streams and descriptor hygiene, identity/policy/state gates, revocation and maintenance races, delivery failure, rollback, logging exemptions and blocked readers. Actual earlier-release installs verify that upgrades invalidate old grants and that new grants work. Root-injected state/ACL/link faults and malformed requests are deliberate fixtures. Real elapsed-expiry, ACPI suspend and SSH/reboot suites from earlier releases were not rerun for 1.0.4; no new evidence for those suites is claimed.

## Native and build checks

Eight Rust tests passed, including the fixed Base64url vector, v1/v2 verifier equivalence, malformed tokens and 20,000 deterministic protocol mutations. Formatting and clippy with warnings denied passed; packaging uses Rust 1.97.1. Rust 1.88 compatibility was established for 1.0.3 and was not rerun for this documentation/link-only release. `cargo audit` reported zero advisories for the locked dependencies on 2026-11-16. The new encoding uses base64 0.22.1. The existing musl libc time_t deprecation warning remains; the tested amd64 ABI is unchanged.

## Public delivery

Publish immutable package, matching allowlisted source, checksum and user-facing guides before changing the pinned HTTPS bootstrap. Public command tests and final browser/download verification are recorded separately after publication in docs/publication/1.0.4-*; this frozen report describes prepublication checks only. Earlier versioned assets remain unchanged. Installation and upgrades invalidate existing grants.

Public source and package documentation exclude internal publication history and local working/debug logs. No private credentials, runtime tokens, VM keys/images or build directories are release inputs. No independent security audit, exhaustive power-cut recovery or support for other architectures, platforms or sudo policies is claimed. See OPERATOR.md and SECURITY_REVIEW.md for the trust boundary and recovery instructions.
