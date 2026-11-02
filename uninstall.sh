#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then echo 'Run with normal administrator sudo: sudo ./uninstall.sh' >&2; exit 1; fi
exec /usr/local/libexec/agent-sudo-helper uninstall
