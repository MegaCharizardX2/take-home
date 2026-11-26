#!/bin/bash
set -euo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive
private_ip=$1
grep -qw avx /proc/cpuinfo

# A missing, partitioned or differently formatted disk must stop provisioning.
disk=/dev/disk/azure/scsi1/lun0
udevadm settle --timeout=90
if [[ ! -b $disk || $(lsblk -nro TYPE "$disk") != disk ]]; then
    echo "Expected a single unpartitioned disk on LUN 0" >&2
    exit 1
fi
fs=$(lsblk -dnro FSTYPE "$disk")
if [[ -z $fs ]]; then
    signatures=$(wipefs --noheadings --output TYPE "$disk")
    if [[ -n $signatures ]]; then
        echo "LUN 0 has an existing disk signature" >&2
        exit 1
    fi
    mkfs.ext4 -L mongo-data "$disk"
elif [[ $fs != ext4 ]]; then
    echo "Expected ext4 on the existing data disk" >&2
    exit 1
fi
uuid=$(blkid -s UUID -o value "$disk")
[[ -n $uuid ]]
install -d -m 0755 /srv/mongodb
if ! awk -v id="UUID=$uuid" '$1 == id && $2 == "/srv/mongodb" {found=1} END {exit !found}' /etc/fstab; then
    if awk '$2 == "/srv/mongodb" {found=1} END {exit !found}' /etc/fstab; then
        echo "Another filesystem already owns the database mount" >&2
        exit 1
    fi
    printf 'UUID=%s /srv/mongodb ext4 defaults,nofail 0 2\n' "$uuid" >> /etc/fstab
fi
mountpoint -q /srv/mongodb || mount /srv/mongodb
[[ $(findmnt -n -o UUID --mountpoint /srv/mongodb) == "$uuid" ]]

apt-get -o Acquire::Retries=3 update -qq
apt-get -o DPkg::Lock::Timeout=180 install -y --no-install-recommends curl jq openssl ca-certificates libcurl4 libssl1.1
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd "$work"
fetch() {
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --retry 3 -o "$1" "$2"
    printf '%s  %s\n' "$3" "$1" | sha256sum --check --status
}
fetch server.tgz https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu2004-6.0.26.tgz \
    dc1e1dc02ddd4cfd18cfae9da668ea672029a6ee749e4e5bf4858b8adaaeb8ed
fetch shell.tgz https://github.com/mongodb-js/mongosh/releases/download/v2.14.3/mongosh-2.14.3-linux-x64-openssl11.tgz \
    af7b14a4865cabd15ef8434a14bd9dcf3f10c03d3ee3ea7d994a260347b4cbbf
fetch tools.deb https://repo.mongodb.org/apt/ubuntu/dists/focal/mongodb-org/6.0/multiverse/binary-amd64/mongodb-database-tools_100.20.1_amd64.deb \
    0503516e8111777bab9d71d94f0df0be857846240a68f6c222100c96084c7da5
mkdir server shell
tar -xzf server.tgz -C server --strip-components=1
tar -xzf shell.tgz -C shell --strip-components=1
install -m 0755 server/bin/mongod /usr/local/bin/mongod
install -m 0755 shell/bin/mongosh /usr/local/bin/mongosh
apt-get -o DPkg::Lock::Timeout=180 install -y "$work/tools.deb"
mongod --version | grep -Fx 'db version v6.0.26' >/dev/null
mongosh --version | grep -Fx '2.14.3' >/dev/null
mongodump --version | grep -Fx 'mongodump version: 100.20.1' >/dev/null

id -u mongodb >/dev/null 2>&1 || useradd --system --home-dir /srv/mongodb --shell /usr/sbin/nologin mongodb
install -d -o mongodb -g mongodb -m 0700 /srv/mongodb/data
cat > /etc/mongod.conf <<CONFIG
storage:
  dbPath: /srv/mongodb/data
net:
  bindIp: 127.0.0.1,$private_ip
  port: 27017
security:
  authorization: enabled
CONFIG
chmod 0644 /etc/mongod.conf
cat > /etc/systemd/system/mongod.service <<'UNIT'
[Unit]
Description=MongoDB
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/srv/mongodb
ConditionPathIsMountPoint=/srv/mongodb
[Service]
User=mongodb
Group=mongodb
ExecStart=/usr/local/bin/mongod --config /etc/mongod.conf
Restart=on-failure
LimitNOFILE=64000
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/mongo-backup.service <<'UNIT'
[Unit]
Description=Upload a daily Tasky backup
Requires=mongod.service
After=mongod.service network-online.target
[Service]
Type=oneshot
UMask=0077
ExecStart=/etc/outpost/backup.sh
TimeoutStartSec=30min
UNIT
cat > /etc/systemd/system/mongo-backup.timer <<'UNIT'
[Unit]
Description=Daily Tasky backup at 10:00 UTC
[Timer]
OnCalendar=*-*-* 10:00:00 UTC
Persistent=true
[Install]
WantedBy=timers.target
UNIT
chmod 0644 /etc/systemd/system/mongod.service /etc/systemd/system/mongo-backup.{service,timer}
systemctl daemon-reload
# Install the kernel block and compressor drop-in before the first mongod start.
bash /etc/outpost/cve-mitigations.sh install
systemctl enable mongod.service
# The protected user-bootstrap step commissions the backup and starts the timer.
systemctl is-active --quiet mongod.service
