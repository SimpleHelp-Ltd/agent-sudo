#!/bin/sh
# HTTPS download bootstrap; only the existing offline installer runs as root.
set -eu
agent_sudo_version=0.1.0
agent_sudo_archive=agent-sudo-0.1.0-linux-amd64.tar.gz
agent_sudo_sha256=6738d229c29ecf033698eadcb3233baac71aac69b5e26f9570eb024ece3f0946
agent_sudo_base=https://tools.simplehelp.io/agent-sudo
fail() { printf 'agent-sudo installer: %s\n' "$*" >&2; exit 1; }
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then fail 'This preview supports Linux amd64 only.'; fi
[ -r /etc/os-release ] || fail 'Cannot identify this OS.'
# OS metadata is supplied by the local operating system.
# shellcheck disable=SC1091
. /etc/os-release
[ "${ID:-}" = ubuntu ] || fail 'This preview supports Ubuntu only.'
case ${VERSION_ID:-} in 24.04|26.04) ;; *) fail 'This preview supports Ubuntu 24.04 and 26.04 only.';; esac
for agent_sudo_command in curl sha256sum tar getent mktemp; do
    command -v "$agent_sudo_command" >/dev/null 2>&1 || fail "Missing dependency: $agent_sudo_command"
done
if [ "$(id -u)" -ne 0 ]; then command -v sudo >/dev/null 2>&1 || fail 'Install sudo first.'; fi
# No implicit recipient: the administrator and agent may be different accounts.
if [ "$#" -eq 0 ]; then
    printf 'Existing account to enroll (no default): ' >/dev/tty
    IFS= read -r agent_sudo_recipient </dev/tty || fail 'A terminal or explicit --user ACCOUNT is required.'
    [ -n "$agent_sudo_recipient" ] || fail 'Select an existing recipient account.'
    set -- --user "$agent_sudo_recipient"
fi
agent_sudo_expect_user=false
for agent_sudo_arg do
    if [ "$agent_sudo_expect_user" = true ]; then
        case "$agent_sudo_arg" in ''|*[!a-zA-Z0-9_.-]*|-*) fail 'Invalid recipient account name.';; esac
        agent_sudo_account=$(getent passwd "$agent_sudo_arg") || fail "Account does not exist: $agent_sudo_arg"
        agent_sudo_uid=$(printf '%s\n' "$agent_sudo_account" | cut -d: -f3)
        [ "$agent_sudo_uid" != 0 ] || fail 'Recipient must be a non-root account.'
        agent_sudo_expect_user=false
    else
        [ "$agent_sudo_arg" = --user ] || fail 'Usage: sh install.sh [--user ACCOUNT ...]'
        agent_sudo_expect_user=true
    fi
done
[ "$agent_sudo_expect_user" = false ] || fail '--user requires an existing account.'
printf 'Installing agent-sudo %s development preview. Loom testing pending.\n' "$agent_sudo_version"
printf 'Enrollment replaces the complete recipient list; reinstalling invalidates all grants.\n'
umask 077
agent_sudo_tmp=$(mktemp -d) || fail 'Cannot create temporary directory.'
trap 'rm -rf -- "$agent_sudo_tmp"' EXIT
trap 'exit 1' HUP INT TERM
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fSL --connect-timeout 15 --max-time 180 \
    "$agent_sudo_base/$agent_sudo_archive" -o "$agent_sudo_tmp/$agent_sudo_archive" || fail 'Download failed; installation was not started.'
printf '%s  %s\n' "$agent_sudo_sha256" "$agent_sudo_tmp/$agent_sudo_archive" | sha256sum -c - || fail 'Checksum mismatch; installation was not started.'
mkdir "$agent_sudo_tmp/payload"
tar -xzf "$agent_sudo_tmp/$agent_sudo_archive" -C "$agent_sudo_tmp/payload" --no-same-owner || fail 'Cannot unpack verified package.'
printf 'Package verified. The offline installer will now request normal administrator authorization.\n'
if [ "$(id -u)" -eq 0 ]; then
    "$agent_sudo_tmp/payload/install.sh" "$@"
else
    sudo -- "$agent_sudo_tmp/payload/install.sh" "$@"
fi
printf 'Installed agent-sudo %s. An administrator can now issue a grant with agent-sudo grant --user ACCOUNT --minutes 60\n' "$agent_sudo_version"
