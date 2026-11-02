# Local validation — agent-sudo 0.1.0

Date: 2026-11-02. Local development preview, not published. Privileged installation/testing occurred only in disposable QEMU/KVM VMs; no host or production privileges were changed. Each VM used 2 vCPUs, 2048 MiB RAM, a qcow2 overlay and user-mode networking with loopback-only SSH forwarding; no host filesystem mounts. Actual installed static Rust binaries were tested, not container substitutes.

## Exact tested systems

| VM | OS | Kernel | Active sudo | Package | visudo |
|---|---|---|---|---|---|
| noble | Ubuntu 24.04.5 LTS amd64 | 6.8.0-147-generic | traditional sudo 1.9.15p5 | 1.9.15p5-3ubuntu5.24.04.4 | 1.9.15p5, grammar 50 |
| resolute | Ubuntu 26.04.1 LTS amd64 | 7.0.0-38-generic | sudo-rs 0.2.13 | 0.2.13-0ubuntu1.2 | visudo-rs 0.2.13 |

Systemd: 255.4-1ubuntu8.18 / 259.5-0ubuntu3.4 respectively. Cloud image SHA-256: noble `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`; resolute `5645d0318ad21f643ebb1ac4567514620e9893380b07b0201fda163baa5b7eb5`, verified against Ubuntu's downloaded SHA256SUMS before boot. Ubuntu 26.04 also contains traditional sudo 1.9.17p2, which was **not** the active/tested backend and is not in the supported preview allowlist.

## Production artifact identity

Both VMs installed these exact release binaries from the local versioned package, with installation policy/owner/mode probes. Core evidence records their hashes; extended/lifecycle runners check hashes before and after their suites, remove stale results and refuse mismatches.

```
agent-sudo
1a500c0c708d6ce889eaadcfb3939af1756236c7b5acd4eecf90e33af6848687
agent-sudo-helper
114f30b27a96186378797ad1c9981b35d800d2e5633f3f7e16b27a2681fa8a52
```

Both binaries independently reproduced byte-for-byte from a relocated source tree with a separate Cargo target directory, locked offline dependencies and the same Rust 1.97.1/musl toolchain. The package build enforces those expected binary hashes. The archive checksum is supplied alongside the final archive; including that checksum inside the archive's own documentation would be circular.

## Actual compiled-binary evidence

| Suite | noble | resolute | Scope |
|---|---:|---:|---|
| Core | 64 pass | 64 pass | CLI, root IDs/context, binary 4 MiB stdin/stdout/stderr, exact argv, child/tool status, hostile direct helper requests, bounds/deadlines, UID/token failures, state/link/ACL corruption, independent enrollment, grants/revoke, PAM, interruption, maintenance races/rollback, logging |
| Extended | 24 pass | 24 pass | Separate result FD, UTF-8 policy, hidden input/echo restoration, high descriptors, hostile stream frames, actual cached-sudo removal, record/list/global/helper/denial caps, stale helper, later logging overrides, delivery failure, early exit/disconnect, hostile environment, delayed readers, input read errors, blocked status output versus revoke, two fresh PAM challenges in one TTY |
| Real wall clock/expiry | 2 pass | 2 pass | Forward/backward one-day wall-clock changes; real one-minute deadline with cleanup stopped; newly issued grant leaves old record/deadline unchanged; admitted 65-second command survives expiry while a future command fails; cleanup then removes expired records |
| Actual ACPI S3 suspend | 1 pass | 1 pass | QMP verified guest `suspended`, 65 seconds suspended, ACPI wakeup, CLOCK_BOOTTIME advanced and one-minute token denied with cleanup stopped |

The initial nonsecret transport prototype adds four separate pre-implementation checks: 262 KB of all byte values and independent binary stderr through each actual sudo; traditional global I/O recording with helper exemption while unrelated commands still recorded; sudo-rs's absence/rejection of traditional I/O logging settings. These prototype checks are not counted as final compiled-binary tests.

**202 compiled-binary VM checks passed (101 per VM)**, plus four separate pre-implementation transport checks.

The remaining 10 checks per VM passed through actual SSH and reboot/removal: secret delivery via SSH stdin to a fresh enrolled session; a second session still requiring the token; live argv/environment/history/journal secrecy scans; reboot invalidating volatile grants; restoring the preboot record still failing boot binding; actual cross-host token rejection; uninstall denying a pending admission; removing all managed files/runtime state/timer; preserving unrelated sudo access and a separate `ops/grant-agent-sudo.sh` fixture; preserving the disabled stable-lock tombstone. Actual package removal was verified in both VMs before shutdown.

The reboot runner needed bounded command timeouts because an SSH connection established just before reboot could otherwise wait on a stale TCP session. This was a harness issue; reconnecting confirmed the guest had rebooted correctly. Final evidence was rerun after fixing it.

## Native/build/dependency checks

- Six Rust native tests passed, including SHA verifier/token shape, binary frames, strict hostile header decoding, UTC formatting and exact deadline equality (the same deadline predicate used by admission).
- Parser mutation test: 20,000 deterministic one-byte mutations plus deep/size boundary inputs; no crash. This is bounded mutation fuzzing, not an unlimited coverage-guided campaign.
- `cargo clippy --locked --all-targets -- -D warnings`, `cargo +1.88.0 check --locked`, shellcheck, Python compilation and Git whitespace checks passed.
- `cargo audit`: 0 vulnerabilities, 0 warnings; RustSec snapshot `857a4a907fed9fdb7c05d66834e960e086fcd698`, 1,401 advisories, 2026-11-02.
- Musl release compilation emits libc's upstream deprecated `time_t` alias notice. The supported amd64 ABI is 64-bit and UTC output is exercised in real grant tests; no unsupported 32-bit/time ABI is claimed.

## Injection versus real integration

Corrupt fields, synthetic exact deadlines, alternate boot/host IDs, account-map inconsistencies, slot/record cap fixtures and hostile filesystem metadata were injected by the VM root test coordinator to exercise fail-closed paths. These are distinct from actual PAM authentication/caching, wall-clock changes, timed expiration, ACPI sleep, SSH and reboot. Upgrade/enrollment/admission and revoke races use installed helper processes. Rollback is forced after replacement by a real systemd enable failure, not an application-only test hook. It is not exhaustive power-cut testing at every installation instruction.

Raw local logs/JSON evidence are under ignored `target/vm`, with commands/settings and safe raw output copied into ignored DEBUGLOG.md. Tokens remain in memory/pipes; grant verifier records exist only in VM runtime state. No private lab SSH key or raw token is included in artifacts.

See SECURITY_REVIEW.md for remaining trust boundaries, unsupported configurations and untested deployment scope. This is not an independent audit.
