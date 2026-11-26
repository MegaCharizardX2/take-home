#!/usr/bin/env bash
# Create the MongoDB users and run the first backup through a managed Run Command.
# MONGODB_URI travels only as a protected parameter inside a mode-0600 request
# body. The guest script's output is never printed: only the execution state and
# exit code. The Run Command resource is always deleted so Azure keeps no copy.
set +x
set -euo pipefail
umask 077
: "${MONGODB_URI:?Missing infra MONGODB_URI}" "${ARM_SUBSCRIPTION_ID:?Missing AZURE_SUBSCRIPTION_ID}"
pattern='^mongodb://tasky:[a-fA-F0-9]+@mongo\.wiz\.internal:27017/\?authSource=admin$'
[[ $MONGODB_URI =~ $pattern ]] || { echo 'MONGODB_URI does not match the Tasky connection contract.' >&2; exit 2; }

api=2025-11-01
vm="/subscriptions/$ARM_SUBSCRIPTION_ID/resourceGroups/takehome-rg/providers/Microsoft.Compute/virtualMachines/vm-mongo"
command="$vm/runCommands/outpost-commission"
url="https://management.azure.com$command?api-version=$api"
private=$(mktemp -d "$RUNNER_TEMP/outpost-commission.XXXXXXXX")

cleanup() {
    rm -rf -- "$private"
    az rest --method delete --url "$url" --only-show-errors --output none >/dev/null 2>&1 ||
        echo 'Warning: could not delete the Run Command resource; delete outpost-commission by hand.' >&2
}
trap cleanup EXIT

location=$(az vm show --ids "$vm" --query location -o tsv --only-show-errors)
[[ $(az vm get-instance-view --ids "$vm" --query "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]" -o tsv --only-show-errors) == PowerState/running ]] ||
    { echo 'vm-mongo is not running. Start it (or wait for the 09:00 schedule) and retry.' >&2; exit 1; }

jq -n --arg location "$location" --arg uri "$MONGODB_URI" '{
    location: $location,
    properties: {
        source: {script: "bash /etc/outpost/commission.sh"},
        protectedParameters: [{name: "MONGODB_URI", value: $uri}],
        asyncExecution: false,
        timeoutInSeconds: 900,
        treatFailureAsDeploymentFailure: true
    }
}' >"$private/body.json"
unset MONGODB_URI

az rest --method put --url "$url" --body "@$private/body.json" --only-show-errors --output none >/dev/null 2>&1 ||
    { echo 'Azure rejected the Run Command request.' >&2; exit 1; }
rm -f -- "$private/body.json"

state=""
view="{}"
for _ in $(seq 1 90); do
    sleep 10
    view=$(az rest --method get --url "$url&\$expand=instanceView" --only-show-errors \
        --query "{state: properties.instanceView.executionState, code: properties.instanceView.exitCode}" -o json 2>/dev/null) || continue
    state=$(jq -r '.state // ""' <<<"$view")
    case "$state" in Succeeded|Failed|TimedOut|Canceled) break ;; esac
done
code=$(jq -r '.code // "unknown"' <<<"$view")
echo "Commission Run Command: state=${state:-unknown} exitCode=$code"
[[ $state == Succeeded && $code == 0 ]] || {
    echo 'Commissioning failed. Inspect the guest privately (journalctl -u mongo-backup, /var/log/azure/run-command-handler) before retrying.' >&2
    exit 1
}
echo 'MongoDB users reconciled and the first backup service run completed.'
