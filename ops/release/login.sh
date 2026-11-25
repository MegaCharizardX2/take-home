#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
uuid='^[[:xdigit:]]{8}(-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}$'
[[ $ARM_CLIENT_ID =~ $uuid && $ARM_TENANT_ID =~ $uuid && $ARM_SUBSCRIPTION_ID =~ $uuid ]] || exit 1
export AZURE_CONFIG_DIR="$RUNNER_TEMP/outpost-azure"
install -d -m 0700 "$AZURE_CONFIG_DIR"
printf 'AZURE_CONFIG_DIR=%s\n' "$AZURE_CONFIG_DIR" >> "$GITHUB_ENV"
jwt=$(curl --proto '=https' --fail --silent --max-time 30 \
    -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" | jq -er '.value | strings | select(length > 0)')
az login --service-principal --username "$ARM_CLIENT_ID" --tenant "$ARM_TENANT_ID" \
    --federated-token "$jwt" --allow-no-subscriptions --only-show-errors -o none >/dev/null 2>&1
unset jwt
# Publisher may have only repository data actions and no visible ARM subscription.
az account show --only-show-errors -o json | jq -e --arg client "$ARM_CLIENT_ID" --arg tenant "$ARM_TENANT_ID" \
    '(.user.name | ascii_downcase) == ($client | ascii_downcase) and (.tenantId | ascii_downcase) == ($tenant | ascii_downcase)' >/dev/null
