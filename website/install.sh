#!/bin/sh
# Parse the complete compound command before any side effects. Keep the closing
# brace as the final byte: every truncated prefix is incomplete or a harmless no-op.
{
# HTTPS download bootstrap; only the existing offline installer runs as root.
set -eu
agent_sudo_version=1.0.3
agent_sudo_archive=agent-sudo-1.0.3-linux-amd64.tar.gz
agent_sudo_sha256=c62253cdf3041a70cbde65593d38aa73c13c7955fdf21132c16f296a29e90565
agent_sudo_base=https://tools.simplehelp.io/agent-sudo
fail() { printf 'agent-sudo installer: %s\n' "$*" >&2; exit 1; }
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then fail 'This release supports Linux amd64 only.'; fi
[ -r /etc/os-release ] || fail 'Cannot identify this OS.'
# OS metadata is supplied by the local operating system.
# shellcheck disable=SC1091
. /etc/os-release
[ "${ID:-}" = ubuntu ] || fail 'This release supports Ubuntu only.'
case ${VERSION_ID:-} in 24.04|26.04) ;; *) fail 'This release supports Ubuntu 24.04 and 26.04 only.';; esac
for agent_sudo_command in curl sha256sum tar mktemp; do
    command -v "$agent_sudo_command" >/dev/null 2>&1 || fail "Missing dependency: $agent_sudo_command"
done
if [ "$(id -u)" -ne 0 ]; then command -v sudo >/dev/null 2>&1 || fail 'Install sudo first.'; fi
[ "$#" -eq 0 ] || fail 'Usage: sh install.sh (no recipient options).'
printf 'Installing agent-sudo %s release.\n' "$agent_sudo_version"
printf 'Installation is machine-wide. Reinstallation invalidates existing grants.\n'
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
printf 'Installed agent-sudo %s. An administrator can now issue a grant with agent-sudo USERNAME MINUTES\n' "$agent_sudo_version"
}