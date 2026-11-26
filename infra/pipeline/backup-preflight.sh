#!/usr/bin/env bash
# Called before a full plan. Never try a public update to prove denial after a waiver exists.
set -euo pipefail
stage=$1
case "$stage" in closed|waiver|public) ;; *) exit 2 ;; esac
resources=$(terraform -chdir=infra state list)
if ! grep -Fxq 'azurerm_disk_encryption_set.mongo' <<<"$resources"; then
    echo 'Complete the disk-encryption-set bootstrap before a full run.' >&2
    exit 1
fi
if grep -Fxq 'azapi_resource.aks' <<<"$resources"; then
    power=$(az aks show -g takehome-rg -n aks-outpost --query powerState.code -o tsv --only-show-errors)
    [[ $power == Running ]] || { echo 'AKS is not running.' >&2; exit 1; }
fi
if grep -Fxq 'azurerm_linux_virtual_machine.mongo' <<<"$resources"; then
    power=$(az vm get-instance-view -g takehome-rg -n vm-mongo \
        --query "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]" -o tsv --only-show-errors)
    [[ $power == PowerState/running ]] || { echo 'Mongo VM is not running.' >&2; exit 1; }
fi
[[ $stage != closed ]] || exit 0
account=$(terraform -chdir=infra output -raw backup_account)
[[ $account =~ ^stoutpost[0-9a-f]{10}$ ]] || { echo 'Invalid backup-account output.' >&2; exit 1; }
if ! grep -Fxq 'azurerm_resource_policy_exemption.backup[0]' <<<"$resources"; then
    if [[ $stage == public ]]; then
        echo 'Complete the denial and waiver run before requesting public access.' >&2
        exit 1
    fi
    bash infra/attempt-public-backup-baseline.sh "$account"
    exit 0
fi
scope="/subscriptions/$ARM_SUBSCRIPTION_ID/resourceGroups/takehome-rg/providers/Microsoft.Storage/storageAccounts/$account"
waiver="$scope/providers/Microsoft.Authorization/policyExemptions/wiz-public-backup-baseline"
assignment="/subscriptions/$ARM_SUBSCRIPTION_ID/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn"
az rest --method get --url "https://management.azure.com$waiver?api-version=2022-07-01-preview" --only-show-errors |
    jq -e --arg id "$waiver" --arg assignment "$assignment" '
      (.id | ascii_downcase) == ($id | ascii_downcase) and
      (.properties.policyAssignmentId | ascii_downcase) == ($assignment | ascii_downcase) and
      .properties.policyDefinitionReferenceIds == ["StorageDisallowPublicAccess"] and
      .properties.exemptionCategory == "Waiver" and
      (.properties.expiresOn | test("^2026-12-08T00:00:00(\\.0+)?(Z|\\+00:00)$"))
    ' >/dev/null
echo 'Verified the account-scoped backup waiver.'
