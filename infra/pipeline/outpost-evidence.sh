#!/usr/bin/env bash
set +x
set -eu
umask 077
exec python3 "$(dirname "$0")/outpost-evidence.py" "$@"
