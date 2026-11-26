#!/bin/bash
set -euo pipefail
umask 077
exec 9>/run/lock/outpost-backup.lock
flock -n 9
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd "$work"
run="$(date -u +%Y%m%dT%H%M%SZ)-$(cat /proc/sys/kernel/random/uuid)"
container=$(cat /etc/outpost/container)
client=$(cat /etc/outpost/client-id)
printf 'Starting backup %s\n' "$run"
mongodump --quiet --config=/etc/outpost/backup.json --db=go-mongodb --archive=dump.archive.gz --gzip
curl --noproxy '*' -fsS --max-time 30 --retry 3 -H 'Metadata: true' \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F&client_id=$client" |
    jq -er '.access_token | select(type=="string" and length>0) | "Authorization: Bearer \(.)"' > auth.header
upload() {
    local status
    status=$(curl --silent --show-error --max-time 300 --output /dev/null --write-out '%{http_code}' \
        --header @auth.header --header 'If-None-Match: *' --header 'x-ms-blob-type: BlockBlob' \
        --header 'x-ms-version: 2023-11-03' --header "x-ms-date: $(LC_ALL=C date -u '+%a, %d %b %Y %T GMT')" \
        --upload-file "$1" "$container/$run/$1")
    if [[ $status != 201 ]]; then
        printf 'Backup %s, %s returned HTTP %s\n' "$run" "$1" "$status" >&2
        return 1
    fi
}
upload dump.archive.gz
jq -n --arg sha "$(sha256sum dump.archive.gz | cut -d' ' -f1)" --argjson size "$(stat -c %s dump.archive.gz)" \
    '{archive:"dump.archive.gz",sha256:$sha,bytes:$size}' > complete.json
upload complete.json
printf 'Completed backup %s\n' "$run"
