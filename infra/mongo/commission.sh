#!/bin/bash
# Managed Run Command supplies MONGODB_URI through a protected parameter in
# the guest environment. Invoke this helper as root after the VM extension.
set -euo pipefail
set +x
umask 077
[[ $EUID == 0 && -n $MONGODB_URI ]]
exec 9>/run/lock/outpost-users.lock
flock 9
export MONGOSH_DISABLE_TELEMETRY=1
mongosh --quiet --norc --host 127.0.0.1 --file /etc/outpost/bootstrap-users.js >/dev/null
unset MONGODB_URI
systemctl enable --now mongo-backup.timer
systemctl start mongo-backup.service
