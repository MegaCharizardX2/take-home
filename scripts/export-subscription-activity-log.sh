#!/usr/bin/env bash
# Run after az login with the subscription Owner's MFA-authenticated user session.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 SUBSCRIPTION_ID WORKSPACE_RESOURCE_GROUP WORKSPACE_NAME" >&2
  exit 2
fi

subscription=$1
setting=wiz-outpost-activity-log
account_type=$(az account show --subscription "$subscription" --query user.type -o tsv)
if [[ "$account_type" != user ]]; then
  echo "Sign in interactively as the lab subscription Owner with MFA." >&2
  exit 1
fi

workspace_id=$(az monitor log-analytics workspace show --subscription "$subscription" \
  --resource-group "$2" --workspace-name "$3" --query id -o tsv)
[[ -n "$workspace_id" ]] || { echo "Workspace lookup returned no resource ID." >&2; exit 1; }

logs=$(jq -nc '["Administrative","Security","ServiceHealth","Alert","Recommendation",
  "Policy","Autoscale","ResourceHealth"] | map({category: ., enabled: true})')
settings=(az monitor diagnostic-settings subscription)
scope=(--subscription "$subscription" --name "$setting")

# Reserve this setting name for the lab. Leave other exports intact on reruns.
existing=$("${settings[@]}" list --subscription "$subscription" -o json |
  jq -c --arg name "$setting" '(.value? // .) | map(select(.name == $name)) | first // empty')
if [[ -z "$existing" ]]; then
  "${settings[@]}" create "${scope[@]}" --location eastus2 \
    --workspace "$workspace_id" --logs "$logs" --output none
fi

# Print the verified setting ID for the panel evidence.
"${settings[@]}" show "${scope[@]}" -o json |
  jq -er --arg dest "$workspace_id" --argjson expected "$logs" '
    if ((.workspaceId // "" | ascii_downcase) == ($dest | ascii_downcase))
       and (([$expected[].category] - [.logs[] | select(.enabled) | .category]) | length == 0)
       and (.id | type == "string" and length > 0)
    then .id
    else error("Activity Log setting does not match the lab workspace and required categories")
    end'
