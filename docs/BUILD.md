# Local builds and VM validation

Linux amd64, Rust 1.97.1 (minimum supported source toolchain 1.88.0), `x86_64-unknown-linux-musl`, musl-tools/linker, Python 3. Dependencies are locked in Cargo.lock. No publishing or host installation step is part of the build.

```sh
rustup target add x86_64-unknown-linux-musl
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo audit
python3 scripts/build-release.py
```

The script sets source and Cargo path remapping, builds static release executables with LTO and stripped symbols, and writes `artifacts/agent-sudo-1.0.4-linux-amd64.tar.gz`, its `.sha256`, and unpacked binaries/scripts/docs/SHA256SUMS. Archive ownership, ordering and times are deterministic. Reproduction requires the same Rust/musl toolchain and locked dependency sources. Packaging accepts `--expected-frontend SHA256 --expected-helper SHA256` to enforce exact tested binaries. `--skip-build` packages already-built candidates; it is not evidence of a fresh build.

VM tests require actual QEMU/KVM Ubuntu cloud images, genisoimage, ssh/scp and Python. They use two local loopback-only SSH forwarded ports 22451/22452, no host filesystem mounts, and test-only accounts/password/key. They never invoke host sudo. Images and checksums are under ignored `target/vm`; SHA256SUMS are downloaded from cloud-images.ubuntu.com. The test harness is privileged **inside the disposable VMs** and deliberately mutates their files, clock, policy and grant state.

```sh
# Download noble/resolute server-cloudimg-amd64.img to target/vm/{noble,resolute}.img
# Verify against their upstream SHA256SUMS before boot.
mkdir -p target/vm
ssh-keygen -t ed25519 -N '' -f target/vm/key
python3 tests/vm/lab.py start
python3 tests/vm/lab.py wait
python3 tests/vm/lab.py info
python3 tests/vm/transport.py              # Run before final installation: temporary nonsecret probe
python3 scripts/build-release.py
python3 tests/vm/run.py                    # Install actual package, core suite
python3 tests/vm/run_extra.py revoke_created # Creator scope/authentication/races
python3 tests/vm/run_extra.py extended
python3 tests/vm/run_extra.py dynamic   # Includes actual 0.1.0 migration fixture
python3 tests/vm/run_extra.py lifecycle    # Two real one-minute expiry runs concurrently
python3 tests/vm/lab.py stop
```

After the guest suites, restart the VMs with QMP enabled (the lab launcher supplies it), then run `python3 tests/vm/suspend.py` and `python3 tests/vm/reboot_ssh.py`. The latter intentionally removes the installation after its SSH/reboot checks. Never point these tests at a real host. Test runner assertions print only names/results, not raw tokens or passwords. Local DEBUGLOG.md and target/vm logs are ignored; secrets are not saved in them. VM SSH keys/fixture credentials are disposable and never reused for a real account.

## Licence files in new releases

The current original source is Apache-2.0. Binary and source distributions must
include `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.txt`. Refresh third-party
notices against the exact locked dependencies, Rust standard library and musl
used for a new build. The local licence change does not republish 1.0.4; select
a new version before distributing a newly packaged release. Existing MIT
release archives and checksums remain unchanged.
