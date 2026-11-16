#!/bin/sh
# Copyright 2026 SimpleHelp
# SPDX-License-Identifier: Apache-2.0

# Offline installer. Deliberately never invokes sudo itself or downloads code.
set -eu
if [ "$(id -u)" -ne 0 ]; then
    echo 'Run with normal administrator sudo: sudo ./install.sh' >&2
    exit 1
fi
case "$0" in */*) agent_sudo_payload=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd);; *) echo 'Invoke using ./install.sh' >&2; exit 1;; esac
cd "$agent_sudo_payload"
sha256sum -c SHA256SUMS
exec ./agent-sudo-helper install --from "$agent_sudo_payload" "$@"
