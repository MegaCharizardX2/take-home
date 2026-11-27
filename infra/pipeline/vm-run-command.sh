#!/usr/bin/env bash
# Outpost database VM operations through managed Azure VM Run Command (no SSH).
#   cve-apply          apply and verify both CVE mitigations (restarts mongod only if needed)
#   cve-verify         read-only verification of both mitigations
#   cve-reboot-verify  restart the VM through ARM, then verify (proves the block persists)
#   backup             run the daily backup service once (write-only role, private endpoint)
# The reviewed guest script travels inside a mode-0600 request body with its
# SHA-256, never on argv. Only the execution state, exit code and a fixed label
# and validated summary fields are printed. The uniquely named Run Command
# resource is always deleted so Azure keeps no copy.
set +x
set -euo pipefail
umask 077
: "${ARM_SUBSCRIPTION_ID:?Missing AZURE_SUBSCRIPTION_ID}" "${RUNNER_TEMP:?Missing RUNNER_TEMP}"
uuid='^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$'
[[ $ARM_SUBSCRIPTION_ID =~ $uuid ]] || { echo 'Invalid subscription ID.' >&2; exit 2; }
mode=${1:-}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "$mode" in
    cve-apply) guest=cve-mitigations.sh arg=apply ;;
    cve-verify | cve-reboot-verify) guest=cve-mitigations.sh arg=verify ;;
    inspect) guest=cve-mitigations.sh arg=inspect ;;
    backup) guest=backup-now.sh arg=run ;;
    *) echo 'Usage: vm-run-command.sh cve-apply|cve-verify|cve-reboot-verify|inspect|backup' >&2; exit 2 ;;
esac
payload="$here/../mongo/$guest"
run_id=${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}
[[ $run_id =~ ^[0-9a-z]+-[0-9]+$ ]] || { echo 'Invalid run identifier.' >&2; exit 2; }

# Fixed, secret-free labels for every guest exit code (test_outpost.py keeps them complete).
label() {
    case $1 in
        0) echo 'ok' ;;
        10) echo 'guest: not root or unknown mode' ;;
        11) echo 'guest: could not identify the OS release' ;;
        12) echo 'guest: could not identify the MongoDB version' ;;
        20) echo 'kernel: module list for the running kernel unreadable' ;;
        21) echo 'kernel: algif_aead is built into the kernel; a modprobe rule cannot block it' ;;
        22) echo 'kernel: could not install the modprobe block rule' ;;
        23) echo 'kernel: algif_aead is loaded and in use; reboot (cve-reboot-verify)' ;;
        24) echo 'kernel: block rule missing or changed' ;;
        25) echo 'kernel: algif_aead is loaded' ;;
        26) echo 'kernel: algif_aead could still be loaded' ;;
        30) echo 'mongod: could not install the compressor drop-in' ;;
        31) echo 'mongod: a backup held the lock for 5 minutes; restart skipped, retry' ;;
        32) echo 'mongod: restart failed' ;;
        33) echo 'mongod: not answering ping on loopback' ;;
        34) echo 'mongod: compressor drop-in missing or changed' ;;
        35) echo 'mongod: /etc/mongod.conf mentions zlib' ;;
        36) echo 'mongod: service not active' ;;
        37) echo 'mongod: running process still allows zlib' ;;
        40) echo 'backup: the backup service failed (writer role, private endpoint or HTTP 201 check)' ;;
        41) echo 'sshd: could not disable and stop ssh' ;;
        42) echo 'sshd: could not verify service state' ;;
        43) echo 'inspect: could not read listening ports' ;;
        90) echo 'wrapper: guest payload missing or checksum mismatch' ;;
        *) echo 'unlabelled exit code' ;;
    esac
}

api=2025-11-01
vm="/subscriptions/$ARM_SUBSCRIPTION_ID/resourceGroups/takehome-rg/providers/Microsoft.Compute/virtualMachines/vm-mongo"
name="outpost-$mode-$run_id"
url="https://management.azure.com$vm/runCommands/$name?api-version=$api"
private=$(mktemp -d "$RUNNER_TEMP/outpost-vm.XXXXXXXX")
created=false

cleanup() {
    rm -rf -- "$private"
    if [[ $created == true ]]; then
        az rest --method delete --url "$url" --only-show-errors --output none >/dev/null 2>&1 ||
            echo "Warning: could not delete the Run Command resource; delete $name by hand." >&2
    fi
}
trap cleanup EXIT

power() {
    az vm get-instance-view --ids "$vm" --query "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]" \
        -o tsv --only-show-errors 2>/dev/null
}
location=$(az vm show --ids "$vm" --query location -o tsv --only-show-errors 2>/dev/null) ||
    { echo 'Could not read vm-mongo.' >&2; exit 1; }
[[ $location =~ ^[a-z0-9]+$ ]] || { echo 'Unexpected vm-mongo location.' >&2; exit 1; }
[[ $(power) == PowerState/running ]] ||
    { echo 'vm-mongo is not running. Start it (or wait for the 09:00 schedule) and retry.' >&2; exit 1; }

if [[ $mode == cve-reboot-verify ]]; then
    az vm restart --ids "$vm" --only-show-errors --output none >/dev/null 2>&1 ||
        { echo 'The vm-mongo restart failed.' >&2; exit 1; }
    for _ in $(seq 1 30); do
        [[ $(power) == PowerState/running ]] && break
        sleep 10
    done
    [[ $(power) == PowerState/running ]] || { echo 'vm-mongo did not return to running.' >&2; exit 1; }
    echo 'vm-mongo restarted through ARM.'
fi

# A POSIX wrapper (the handler's shell is not assumed): decode the reviewed
# script, check its hash, run it with bash, always remove it.
sha=$(sha256sum "$payload" | cut -d' ' -f1)
{
    printf '#!/bin/sh\nset -u\numask 077\nf=$(mktemp) || exit 90\n'
    printf "if ! base64 -d >\"\$f\" <<'OUTPOST_PAYLOAD'\n"
    base64 <"$payload" | fold -w 76
    printf 'OUTPOST_PAYLOAD\nthen rm -f "$f"; exit 90; fi\n'
    printf 'if ! printf "%%s  %%s\\n" %s "$f" | sha256sum -c --status; then rm -f "$f"; exit 90; fi\n' "$sha"
    printf 'bash "$f" %s\nstatus=$?\nrm -f "$f"\nexit "$status"\n' "$arg"
} >"$private/script.sh"
jq -n --arg location "$location" --rawfile script "$private/script.sh" '{
    location: $location,
    properties: {
        source: {script: $script},
        asyncExecution: false,
        timeoutInSeconds: 900,
        treatFailureAsDeploymentFailure: true
    }
}' >"$private/body.json"

created=true
az rest --method put --url "$url" --body "@$private/body.json" --only-show-errors --output none >/dev/null 2>&1 ||
    { echo 'Azure rejected the Run Command request.' >&2; exit 1; }
rm -f -- "$private/body.json" "$private/script.sh"

state=""
view="{}"
fields="state: properties.instanceView.executionState, code: properties.instanceView.exitCode"
if [[ $mode != backup ]]; then
    fields+=", output: properties.instanceView.output"
fi
for _ in $(seq 1 90); do
    sleep 10
    view=$(az rest --method get --url "$url&\$expand=instanceView" --only-show-errors \
        --query "{$fields}" -o json 2>/dev/null) || continue
    state=$(jq -r '.state // ""' <<<"$view")
    case "$state" in Succeeded|Failed|TimedOut|Canceled) break ;; esac
done
case "$state" in Succeeded|Failed|TimedOut|Canceled) ;; *) state=unknown ;; esac
code=$(jq -r 'if (.code | type) == "number" then .code else "unknown" end' <<<"$view")
label=$(label "$code")
echo "VM Run Command $mode: state=${state:-unknown} exitCode=$code ($label)"
[[ $state == Succeeded && $code == 0 ]] || {
    echo 'The guest step failed. Inspect privately on the VM (journalctl -t outpost-cve, /var/log/azure/run-command-handler).' >&2
    exit 1
}
# Validate the entire field (including control characters) before passing any
# remote text to the shell. The handler may include one final line ending.
if [[ $mode == backup ]]; then
    echo 'The backup service uploaded a new backup through the private endpoint.'
elif [[ $mode == inspect ]]; then
    jq -er '
        .output | capture("\\A(?<os>[a-z][a-z0-9_-]{0,31}) (?<version>[0-9]{1,4}(?:\\.[0-9]{1,4}){0,2}) (?<db>[0-9]{1,3}(?:\\.[0-9]{1,3}){2}) (?<boot>enabled|disabled|masked|static) (?<active>active|inactive|failed|activating|deactivating) (?<ports>none|(?:tcp|udp)/[1-9][0-9]{0,4}(?:,(?:tcp|udp)/[1-9][0-9]{0,4})*)\\r?\\n?\\z")
        | select(.ports == "none" or (.ports | split(",") | all(.[]; split("/")[1] | tonumber <= 65535)))
        | "OS=\(.os) \(.version) MongoDB=\(.db) sshd=\(.boot)/\(.active) listening_ports=\(.ports)"
    ' <<<"$view" 2>/dev/null || { echo 'Invalid VM inspect summary.' >&2; exit 1; }
else
    jq -er '
        .output | capture("\\Akernel=(?<kernel>verified|not-applicable) mongo=(?<mongo>verified|not-applicable)\\r?\\n?\\z")
        | "sshd=disabled/inactive CVE-2026-31431=\(.kernel) CVE-2025-14847=\(.mongo)"
    ' <<<"$view" 2>/dev/null || { echo 'Invalid VM mitigation summary.' >&2; exit 1; }
fi
