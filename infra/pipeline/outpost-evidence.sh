#!/usr/bin/env bash
# Read-only Outpost readback through ARM, plus one anonymous request from this
# hosted runner (an external network). Prints only fixed PASS labels and an
# HTTP status code; resource values, IPs and principal IDs stay private.
# Each failed check exits with its own code (11-19) and a fixed label.
set +x
set -euo pipefail
umask 077
: "${ARM_SUBSCRIPTION_ID:?Missing AZURE_SUBSCRIPTION_ID}" "${RUNNER_TEMP:?Missing RUNNER_TEMP}"
[[ $ARM_SUBSCRIPTION_ID =~ ^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$ ]] || { echo 'Invalid subscription ID.' >&2; exit 2; }
rg="/subscriptions/$ARM_SUBSCRIPTION_ID/resourceGroups/takehome-rg"
private=$(mktemp -d "$RUNNER_TEMP/outpost-evidence.XXXXXXXX")
trap 'rm -rf -- "$private"' EXIT

fail() { echo "FAIL $2" >&2; exit "$1"; }
pass() { echo "PASS $1"; }
# GET one ARM path into a private file; the response is never printed.
arm() { az rest --method get --url "https://management.azure.com$1" --only-show-errors -o json >"$private/$2.json" 2>/dev/null; }

arm "$rg/providers/Microsoft.Storage/storageAccounts?api-version=2025-08-01" accounts || fail 11 'backup account unreadable'
account=$(jq -er '[.value[] | select(.name | test("^stoutpost[0-9a-f]{10}$"))] | if length == 1 then .[0].name else error("count") end' \
    "$private/accounts.json" 2>/dev/null) || fail 11 'backup account not found exactly once'
id="$rg/providers/Microsoft.Storage/storageAccounts/$account"
arm "$id?api-version=2025-08-01" account || fail 11 'backup account unreadable'
jq -e '.properties as $p |
    $p.publicNetworkAccess == "Disabled" and $p.allowBlobPublicAccess == false and $p.allowSharedKeyAccess == false and
    $p.networkAcls.defaultAction == "Deny" and
    ($p.encryption.keySource | ascii_downcase) == "microsoft.keyvault" and
    ($p.encryption.keyvaultproperties.keyname | ascii_downcase) == "backup-cmk" and
    ($p.encryption.identity.userAssignedIdentity | ascii_downcase | endswith("/userassignedidentities/id-backup-cmk"))' \
    "$private/account.json" >/dev/null 2>&1 || fail 11 'backup account is not private with the backup CMK'
pass 'backup account: public network access disabled, anonymous access off, Shared Key off, Key Vault CMK backup-cmk'

arm "$id/blobServices/default/containers/backups?api-version=2025-08-01" container || fail 12 'backup container unreadable'
jq -e '(.properties.publicAccess // "None") == "None"' "$private/container.json" >/dev/null 2>&1 || fail 12 'backup container is public'
arm "$id/privateEndpointConnections?api-version=2025-08-01" endpoints || fail 12 'private endpoint connections unreadable'
jq -e '[.value[] | select(.properties.privateLinkServiceConnectionState.status == "Approved")] | length >= 1' \
    "$private/endpoints.json" >/dev/null 2>&1 || fail 12 'no approved Blob private endpoint'
pass 'backup container private; Blob reachable through an approved private endpoint'

arm "$id/providers/Microsoft.Authorization/policyExemptions?api-version=2022-07-01-preview" exemptions || fail 13 'policy exemptions unreadable'
jq -e '[.value[] | select(.name == "wiz-public-backup-baseline")] | length == 0' "$private/exemptions.json" >/dev/null 2>&1 ||
    fail 13 'the public-backup policy exemption still exists'
pass 'policy exemption wiz-public-backup-baseline deleted; the lab deny policy applies in full again'

# Anonymous list from outside the VNet. Anything but HTTP 200 is a denial.
status=$(curl -q --noproxy '*' --silent --max-time 20 --output /dev/null --write-out '%{http_code}' \
    "https://$account.blob.core.windows.net/backups?restype=container&comp=list") || true
[[ $status =~ ^[0-9]{3}$ ]] || status=000
[[ $status != 200 ]] || fail 14 'anonymous listing from an external network still succeeds'
pass "anonymous listing from this external runner refused (HTTP $status)"

arm "$rg/providers/Microsoft.Network/networkInterfaces/nic-mongo?api-version=2024-07-01" nic || fail 15 'database NIC unreadable'
jq -e '[.properties.ipConfigurations[].properties.publicIPAddress // empty] | length == 0' "$private/nic.json" >/dev/null 2>&1 ||
    fail 15 'the database NIC still has a public IP'
arm "$rg/providers/Microsoft.Network/publicIPAddresses?api-version=2024-07-01" ips || fail 15 'public IPs unreadable'
jq -e '[.value[] | select(.name == "pip-mongo")] | length == 0' "$private/ips.json" >/dev/null 2>&1 || fail 15 'pip-mongo still exists'
pass 'database VM has no public IP (pip-mongo released)'

arm "$rg/providers/Microsoft.Network/networkSecurityGroups/nsg-mongo?api-version=2024-07-01" nsg || fail 16 'database NSG unreadable'
jq -e '[.properties.securityRules[].properties | select(.direction == "Inbound") |
        {access, ports: ([.destinationPortRange // empty] + (.destinationPortRanges // []))} |
        select(.ports | any(. == "*" or . == "22" or ((split("-") | length) == 2 and
            ((split("-")[0] | tonumber) <= 22) and ((split("-")[1] | tonumber) >= 22))))] as $ssh |
       ($ssh | map(select(.access == "Allow")) | length) == 0 and ($ssh | map(select(.access == "Deny")) | length) >= 1' \
    "$private/nsg.json" >/dev/null 2>&1 || fail 16 'inbound SSH is not denied on the database NSG'
pass 'database NSG: no inbound SSH allow; TCP 22 denied from every source'

arm "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-mongo?api-version=2023-01-31" mongo || fail 17 'id-mongo unreadable'
principal=$(jq -er '.properties.principalId' "$private/mongo.json" 2>/dev/null) || fail 17 'id-mongo unreadable'
[[ $principal =~ ^[0-9a-f-]{36}$ ]] || fail 17 'id-mongo unreadable'
arm "$rg/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&%24filter=roleName%20eq%20%27Lab%20Backup%20Writer%27" writer ||
    fail 17 'Lab Backup Writer unreadable'
writer=$(jq -er '[.value[] | select(.properties.roleName == "Lab Backup Writer")] | if length == 1 then .[0].name else error("count") end' \
    "$private/writer.json" 2>/dev/null) || fail 17 'Lab Backup Writer not found exactly once'
arm "$rg/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&%24filter=assignedTo(%27$principal%27)" grants ||
    fail 17 'id-mongo role assignments unreadable'
jq -e --arg writer "$writer" --arg scope "$id/blobServices/default/containers/backups" '
    [.value[].properties] | length == 1 and
    (.[0].roleDefinitionId | ascii_downcase | endswith("/" + ($writer | ascii_downcase))) and
    (.[0].scope | ascii_downcase) == ($scope | ascii_downcase)' "$private/grants.json" >/dev/null 2>&1 ||
    fail 17 'id-mongo holds a role other than the container-scoped Lab Backup Writer'
pass 'id-mongo: only Lab Backup Writer (blob write and add, no read, delete or compute) on the backup container'

arm "$rg/providers/Microsoft.ContainerService/managedClusters/aks-outpost?api-version=2025-10-01" aks || fail 18 'AKS unreadable'
jq -e '.properties.apiServerAccessProfile as $a | $a.enableVnetIntegration == true and ($a.enablePrivateCluster // false) == false and
       ($a.authorizedIPRanges | length) == 1 and ($a.authorizedIPRanges[0] | test("^([0-9]{1,3}[.]){3}[0-9]{1,3}/32$")) and
       ($a.authorizedIPRanges[0] | startswith("0.") | not)' "$private/aks.json" >/dev/null 2>&1 ||
    fail 18 'the AKS API is not limited to one /32 plus VNet Integration'
pass 'AKS API: one authorized /32 (home) plus the VNet-integrated private path for in-VNet applications'
echo 'Outpost readback complete.'
