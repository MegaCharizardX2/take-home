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
private_first=false
if grep -Fxq 'azurerm_storage_account.backup' <<<"$resources"; then
    if ! grep -Fxq 'azurerm_key_vault_key.backup' <<<"$resources" ||
       ! grep -Fxq -e 'azurerm_role_assignment.backup_cmk' -e 'azurerm_role_assignment.lab["cmk"]' <<<"$resources"; then
        echo 'The backup key and its id-backup-cmk grant must exist before the CMK switch.' >&2
        exit 1
    fi
    # A completed Outpost apply records backup_stage. A partially applied step A
    # may already have closed storage before the new output was saved.
    private_first=$(terraform -chdir=infra show -json | jq -r '
        .values as $state |
        [$state.root_module.resources[] | select(.address == "azurerm_storage_account.backup")] |
        if length != 1 then error("Missing backup account state") else .[0].values end |
        if (.public_network_access_enabled | type) != "boolean" then error("Missing storage network state") else . end |
        ($state.outputs.backup_stage.value != "outpost" and
         .public_network_access_enabled == true and
         ((.customer_managed_key // []) | length) == 0)')
    case "$private_first" in
        true|false) ;;
        *) echo 'Could not identify the backup storage step.' >&2; exit 1 ;;
    esac
fi
printf 'private_first=%s\n' "$private_first" >> "$GITHUB_OUTPUT"
echo 'Verified power state and the backup CMK prerequisites.'
