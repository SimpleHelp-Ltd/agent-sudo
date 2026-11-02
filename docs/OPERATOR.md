# Operator guide

## Trust and support

This grants full root authority to a trusted operator. No saved administrator password. Tokens are bearer credentials bound to a Linux account, host and current boot. Other processes using that UID may inspect token input/memory; separate accounts improve operational separation. Future command admissions stop at expiry, revocation and reboot. Existing root commands, descendants and root shells continue, and root can establish permanent access. Existing sudo permissions/caches are independent. There is no network service or command allowlist.

The preview supports Ubuntu 24.04/26.04 amd64 with systemd and the exact sudo release families in VALIDATION.md. It rejects custom sudo.conf settings/plugins, remote includes, continued policy lines, external command-scoped Defaults, explicit recording command tags and unsupported subcommand/remote recording. Traditional sudo uses a command-scoped I/O logging exemption for the helper; all other audit and sudo permissions are retained. sudo-rs 0.2.13 has no I/O logger and rejects its configuration options. Host tracing, PAM customizations, eBPF/audit capture and privileged debugging remain outside the tool's secrecy guarantee. Root-only policy edits require revalidation, not an automatic exemption or silent change to other rules.

## Install, enroll and upgrade

Use only the offline versioned package from a trusted build. Verify its archive checksum through a trusted channel; a checksum delivered with untrusted code is not a signature. Start in disposable VMs and keep an independent administrator session open.

```sh
sha256sum -c agent-sudo-0.1.0-linux-amd64.tar.gz.sha256
tar -xzf agent-sudo-0.1.0-linux-amd64.tar.gz
sudo ./install.sh --user agent --user second-agent
```

Specify the **complete** enrollment set each time. The accounts must already exist. Installer requires normal root authorization, freezes payload bytes, validates file ownership/ACLs, detects unmanaged/modified files, disables admissions and invalidates grants under the stable maintenance lock, atomically replaces managed files, validates actual sudoers and probes transport/effective permissions, starts the cleanup timer and commits a new generation last. Unsupported policies fail closed. No broad root rule is added. Run the same installer for upgrades or enrollment/policy changes; **all existing grants become unusable**. Detectable failed installations restore prior managed files/configuration, without resurrecting old grants. A power loss may leave installation disabled or a partial set requiring manual recovery; do not treat this as a cross-file atomic filesystem transaction.

The helper is a root-owned compiled executable, never a script loaded from a checkout. It is mode 0755, without setuid. The tool does not modify SSH, unrelated sudoers files or `ops/grant-agent-sudo.sh`.

## Grant and use

```sh
agent-sudo                            # Prompts, defaults: current account / 60 minutes
agent-sudo grant --user agent --minutes 60
```

The grant requests fresh sudo authentication using `sudo -k` with a command; the app does not prompt for, handle or save an administrator password. Passwordless administrator policy may not challenge. Token stdout is intentionally secret; do not redirect to logs, paste into shell commands, or capture terminal output in a recording session. Metadata/revocation instructions go to stderr. The displayed host is the machine-id, not DNS identity.

```sh
agent-sudo run -- /usr/bin/id </dev/null
agent-sudo run -- /bin/cat < input.bin > output.bin
agent-sudo run -- /bin/sh -c 'explicit shell command' </dev/null
agent-sudo status
agent-sudo revoke GRANT-ID
agent-sudo revoke --all
agent-sudo admin list
agent-sudo admin revoke GRANT-ID
```

Run has no PTY or terminal emulation; redirect command stdin. Its hidden prompt uses `/dev/tty`. A nonsecret preflight checks current enrollment/policy before asking for a token. The actual run checks again before receiving the token, avoiding a privileged helper waiting while a human types. `--key-fd N` reads one newline-terminated (or EOF-terminated) token, closes that descriptor before actual run sudo, and keeps command stdin independent. No positional key, token environment variable, automatic plaintext key file, fallback elevation, user-selected root environment or cwd.

Root programs get real/effective/saved UID/GID 0, empty supplementary groups, `/root` cwd, umask 077, fixed HOME/USER/LOGNAME/SHELL/PATH/LANG, core limit zero, and only intended stdin/stdout/stderr. Executables must be absolute. Arguments must be UTF-8 without NUL (<=256, <=4096 bytes each, <=32768 bytes total, also subject to 64 KiB encoded header). Shell expansion occurs only when an explicit shell is requested.

Streams are binary and bounded, with backpressure. SIGINT/TERM/HUP to the frontend forward through sudo to the foreground child process group. A framed signal request is also supported by the helper. Foreground disconnect triggers best-effort termination; deliberately detached root work cannot be contained. After the leader exits, idle inherited output pipes close after a two-second grace period; buffered output still drains under backpressure. Continuously writing descendants may keep streams active; background jobs should redirect their streams. Full terminal apps/editors/GUI programs are unsupported.

Child exits propagate, signals map to 128+signal; tool errors return 125. Because an actual child may also exit 125, automation should use `--result-fd N`. That separate descriptor receives exactly one final JSON object: `{"kind":"exit","code":125,"signal":null}` versus `{"kind":"error","message":"..."}`. Child stdout/stderr never enter it. The descriptor must differ from `--key-fd` and be >=3. `--json-result` writes a convenience final object to stderr; arbitrary child stderr can resemble it, so it is not the unambiguous automation channel. Loss of the final helper frame or a sudo failure is never command success.

## SSH token delivery (tested)

Python owns the token in memory; shell history, command arguments, environment and files never contain it. SSH host-key/authentication policy must already be configured. This needs no extra descriptor preserved by sudo:

```sh
python3 - <<'PY'
import getpass, subprocess
key = getpass.getpass('Agent token: ')
subprocess.run([
    'ssh', 'agent@backup-host',
    'exec agent-sudo run --key-fd 3 -- /usr/bin/id 3<&0 </dev/null'
], input=(key + '\n').encode(), check=True)
PY
```

The remote shell duplicates SSH input to frontend fd 3 and uses `/dev/null` for command stdin. The frontend consumes/closes fd 3; the helper receives a framed request over normal sudo stdin. Do not embed the key in `ssh` command strings or shell variables under `set -x`. This example intentionally uses no command input; sending a token and separate binary stdin over one SSH stream would need a separate trusted framing wrapper.

## State and lifecycle

`/run/agent-sudo` is root 0700; grant records are 0600 with single links, no symlinks/extended ACLs. Only a SHA-256 verifier is stored. Random tokens have 256 secret bits and 128-bit nonsecret IDs. Account UID/name/enrollment generation, machine ID, boot ID and CLOCK_BOOTTIME expiry are checked on admission. Suspension counts; wall time affects display only. Same-name/same-UID account recreation is not reliably detectable: revoke all grants before account changes.

An exclusive stable lock orders admission, issuance, revocation, cleanup and maintenance. Admission ordered before revoke/expiry may start later or continue; later admissions fail. No command-lifetime lock. A five-second header deadline applies only once the helper is ready; <=32 pending helpers globally, <=4 per UID, <=128 grants/enrollments, bounded listings and 10/min denial audit messages. Sudo's own launch/authentication resource use is still subject to OS limits, not a complete DoS defense. New grants never extend old ones. Stop cleanup if needed: expiry enforcement does not depend on it.

The frontend acknowledges successful token output. Detectable write failure or missing acknowledgment revokes the grant. A crash after acknowledgment or uncertain delivery may leave a live grant; list/revoke it (or revoke-all). Lost secrets cannot be recovered. Token/verifier deletion is not secure erasure. RAM can be captured by root; key buffers are zeroized where practical, core dumps disabled, but swap/privileged debugging cannot be ruled out.

Audit events contain operation, grant ID, actor/recipient UID, timestamps and executable path; not argv or streams. Denial logs are rate limited and do not describe submitted secrets. Routine logs contain no raw tokens or verifiers. Operators must inspect external recording/tracing policy separately.

## Remove and independent recovery

```sh
sudo ./uninstall.sh
# or:
sudo /usr/local/libexec/agent-sudo-helper uninstall
```

Removal disables control and the enrollment rule first, validates remaining sudoers, stops/disables cleanup, removes runtime state and only owned managed files. It retains a root-only disabled `/var/lib/agent-sudo` control/lock tombstone: never unlink the live lock while old helpers may exist. Other sudo access is preserved.

If files were modified, normal removal/upgrade deliberately refuses to overwrite them. From an **independent administrator session**, remove `/etc/sudoers.d/agent-sudo` first, run the installed `visudo -c`, disable/stop `agent-sudo-cleanup.timer`, mark `/var/lib/agent-sudo/config` disabled (or remove config), remove `/run/agent-sudo`, then remove the managed binaries, units and tmpfiles config below and run `systemctl daemon-reload`. Preserve `/var/lib/agent-sudo/lock` and its directory until every old helper has exited. Do not delete unrelated sudoers policy or replace `/etc/sudoers`.

Managed paths: `/usr/local/bin/agent-sudo`, `/usr/local/libexec/agent-sudo-helper`, `/etc/sudoers.d/agent-sudo`, `/etc/systemd/system/agent-sudo-cleanup.{service,timer}`, `/etc/tmpfiles.d/agent-sudo.conf`; control/manifest/lock under `/var/lib/agent-sudo`. If root work created persistence, removing this application does not revoke that independent access.
