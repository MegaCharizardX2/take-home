#!/usr/bin/env bash
# Attached to the AKS Run Command pod. Only fixed result markers leave this script.
set -euo pipefail
umask 077
exec 3>&1
exec >/dev/null 2>&1
result() { printf '%s\n' "$1" >&3; }
fail() { result "$1"; exit 1; }
k() { kubectl --request-timeout=20s "$@"; }
subscription=$1
run=$2
[[ $subscription =~ ^[0-9a-fA-F-]{36}$ && $run =~ ^[0-9]+-[0-9]+$ ]] || fail 'FAIL preflight'
private=$(mktemp -d)
trap 'rm -rf -- "$private"' EXIT

# Start the alert clock first. Refuse the app's actual binding or a replacement
# object. The manifest owner supplies this inert binding in the next delivery.
binding=wiz-panel-demo
format='{{index .metadata.labels "app.kubernetes.io/part-of"}}|{{.roleRef.apiGroup}}|{{.roleRef.kind}}|{{.roleRef.name}}|{{if .subjects}}bound{{else}}empty{{end}}|{{.metadata.resourceVersion}}'
record=$(k get clusterrolebinding "$binding" -o "go-template=$format") || fail 'FAIL binding guard'
IFS='|' read -r owner group kind role subjects version <<<"$record"
[[ $owner == outpost && $group == rbac.authorization.k8s.io && $kind == ClusterRole &&
   $role == view && $subjects == empty && -n $version ]] || fail 'FAIL binding guard'
k annotate clusterrolebinding "$binding" "outpost.wiz.internal/panel-run=$run" \
    --resource-version="$version" --overwrite -o name || fail 'FAIL binding annotation'
result 'PASS binding annotation'

image=$(k -n wiz-web get deployment web -o 'jsonpath={.spec.template.spec.containers[?(@.name=="web")].image}') ||
    fail 'FAIL deployed image'
[[ $image =~ ^acroutpost[0-9a-f]{10}\.azurecr\.io/tasky@sha256:[0-9a-f]{64}$ ]] || fail 'FAIL deployed image'

cluster="/subscriptions/$subscription/resourceGroups/takehome-rg/providers/Microsoft.ContainerService/managedClusters/aks-outpost"
assignment="$cluster/providers/Microsoft.Authorization/policyAssignments/deny-privileged"
definition='/providers/Microsoft.Authorization/policyDefinitions/95edb821-ddaf-4404-9732-666045e056b4'
format='{{range .items}}{{.metadata.name}}|{{index .metadata.annotations "azure-policy-assignment-id"}}|{{index .metadata.annotations "azure-policy-definition-id"}}|{{.spec.enforcementAction}}{{"\n"}}{{end}}'
constraint=$(k get k8sazurev2noprivilege.constraints.gatekeeper.sh -o "go-template=$format" |
    awk -F'|' -v a="$assignment" -v d="$definition" \
    'tolower($2)==tolower(a) && tolower($3)==tolower(d) && tolower($4)=="deny" {print $1}') ||
    fail 'FAIL policy attribution'
[[ $constraint =~ ^[a-z0-9][a-z0-9.-]*$ ]] || fail 'FAIL policy attribution'

dry_run() {
    local overrides
    overrides=$(printf '{"spec":{"automountServiceAccountToken":false,"securityContext":{"runAsNonRoot":true,"runAsUser":10001,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"panel-policy-check","securityContext":{"privileged":%s,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}' "$1")
    k -n wiz-web run panel-policy-check --restart=Never --image="$image" \
        --override-type=strategic --overrides="$overrides" --dry-run=server -o name
}
dry_run false || fail 'FAIL ordinary pod'
result 'PASS ordinary pod admitted'
if dry_run true 2>"$private/denial"; then fail 'FAIL privileged pod admitted'; fi
if ! grep -Fq 'admission webhook "validation.gatekeeper.sh" denied the request' "$private/denial" ||
   ! grep -Fq -e "[$constraint]" -e "[denied by $constraint]" "$private/denial" ||
   ! grep -Fq 'Privileged container is not allowed' "$private/denial"; then
    fail 'FAIL wrong denial'
fi
result 'PASS privileged pod denied by deny-privileged'
