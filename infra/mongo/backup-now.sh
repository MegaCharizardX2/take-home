#!/bin/bash
# Run the daily backup service once, as root, through Azure VM Run Command.
# backup.sh uploads with the VM identity's write-only role over the Blob private
# endpoint and fails unless both Put Blob requests return HTTP 201. Nothing is
# printed; the exit code is mapped to a fixed label by vm-run-command.sh.
set -uo pipefail
[[ ${1:-} == run && $(id -u) == 0 ]] || exit 10
exec >/dev/null 2>&1
systemctl start mongo-backup.service || exit 40
exit 0
