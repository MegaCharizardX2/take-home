#!/usr/bin/env bash
# Called by the protected infra job between the closed and waiver stages.
set -euo pipefail
account=$1
if [[ ! $account =~ ^stoutpost[0-9a-f]{10}$ ]]; then
    echo "Expected the generated lab backup account name." >&2
    exit 1
fi
group=takehome-rg
current=$(az storage account show -g "$group" -n "$account" -o json)
jq -e '.allowBlobPublicAccess == false and .tags.owner == "takehome"' <<<"$current" >/dev/null
scope=$(jq -er .id <<<"$current")
subscription=$(az account show --query id -o tsv)
expected="/subscriptions/$subscription/resourceGroups/$group/providers/Microsoft.Storage/storageAccounts/$account"
jq -ne --arg actual "$scope" --arg expected "$expected" '($actual | ascii_downcase) == ($expected | ascii_downcase)' >/dev/null
# An unexpected policy allow must never briefly expose an old container ACL.
az rest --method get --url "https://management.azure.com$scope/blobServices/default/containers?api-version=2025-08-01" \
    --only-show-errors | jq -e '
      (.nextLink // "") == "" and (.value | length) == 1 and
      .value[0].name == "backups" and (.value[0].properties.publicAccess // "None") == "None"
    ' >/dev/null
assignment="/subscriptions/$subscription/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn"
error=$(mktemp)
trap 'rm -f -- "$error"' EXIT
endpoint="https://management.azure.com$scope?api-version=2025-08-01"
if az rest --method patch --url "$endpoint" --body '{"properties":{"allowBlobPublicAccess":true}}' -o none 2>"$error"; then
    az rest --method patch --url "$endpoint" --body '{"properties":{"allowBlobPublicAccess":false}}' -o none
    echo "The expected policy denial did not occur. Closed the account again." >&2
    exit 1
fi
grep -Fq 'RequestDisallowedByPolicy' "$error"
grep -Fiq "$assignment" "$error"
grep -Fq 'StorageDisallowPublicAccess' "$error"
az storage account show -g "$group" -n "$account" -o json | jq -e '.allowBlobPublicAccess == false' >/dev/null
printf 'RequestDisallowedByPolicy for %s under %s (StorageDisallowPublicAccess)\n' "$scope" "$assignment"
