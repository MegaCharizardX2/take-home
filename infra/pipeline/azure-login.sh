#!/usr/bin/env bash
# The repository allowlist permits GitHub actions and the pinned Terraform tools.
set +x
set -euo pipefail
umask 077
: "${ARM_CLIENT_ID:?Missing AZURE_CLIENT_ID}" "${ARM_SUBSCRIPTION_ID:?Missing AZURE_SUBSCRIPTION_ID}" "${ARM_TENANT_ID:?Missing AZURE_TENANT_ID}"
export AZURE_CONFIG_DIR="$RUNNER_TEMP/outpost-azure"
install -d -m 0700 "$AZURE_CONFIG_DIR"
printf 'AZURE_CONFIG_DIR=%s\n' "$AZURE_CONFIG_DIR" >> "$GITHUB_ENV"

jwt=$(curl --proto '=https' --fail --silent --show-error --max-time 30 \
    -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" |
    jq -er '.value | select(type == "string" and length > 0)')
az login --service-principal --username "$ARM_CLIENT_ID" --tenant "$ARM_TENANT_ID" \
    --federated-token "$jwt" --only-show-errors --output none >/dev/null 2>&1 || {
    echo 'Azure OIDC sign-in failed.' >&2
    exit 1
}
unset jwt
az account set --subscription "$ARM_SUBSCRIPTION_ID" --only-show-errors
actual=$(az identity show -g takehome-rg -n takehome-id --query clientId -o tsv --only-show-errors)
shopt -s nocasematch
if [[ -z $actual || "$actual" != "$ARM_CLIENT_ID" ]]; then
    echo 'OIDC client does not match takehome-id in the lab subscription.' >&2
    exit 1
fi
