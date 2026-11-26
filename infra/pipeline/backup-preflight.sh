#!/usr/bin/env bash
# Called before a full plan: both workloads must be running, and the CMK
# prerequisites must already be in state before the backup account switches keys.
set -euo pipefail
stage=$1
[[ $stage == outpost ]] || { echo 'Only the outpost stage can be planned.' >&2; exit 2; }
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
if grep -Fxq 'azurerm_storage_account.backup' <<<"$resources"; then
    # The live account switches to the customer-managed key in this plan.
    grep -Fxq 'azurerm_key_vault_key.backup' <<<"$resources" &&
        grep -Fxq -e 'azurerm_role_assignment.backup_cmk' -e 'azurerm_role_assignment.lab["cmk"]' <<<"$resources" ||
        { echo 'The backup key and its id-backup-cmk grant must exist before the CMK switch.' >&2; exit 1; }
fi
echo 'Verified power state and the backup CMK prerequisites.'
