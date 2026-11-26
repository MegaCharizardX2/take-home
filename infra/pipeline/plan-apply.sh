#!/usr/bin/env bash
# One private saved plan per phase. The scanner sees only its JSON and the IaC.
set +x
set -euo pipefail
umask 077
: "${TF_VAR_ssh_public_key:?Missing infra SSH_PUBLIC_KEY}" "${TF_VAR_alert_email:?Missing infra ALERT_EMAIL}"
: "${TF_VAR_aks_api_home_cidr:?Missing infra AKS_API_HOME_CIDR}"
mode=$1
stage=$2
# Outpost is one-way: the Phase-1 closed, waiver and public stages are retired.
[[ $stage == outpost ]] || { echo 'Only the outpost stage can be planned.' >&2; exit 2; }
targets=()
case "$mode" in
    foundation) targets=(-target=azurerm_role_assignment.crypto_officer) ;;
    # A fresh build grants the CMK identity on its key well before the account uses it.
    vault-and-keys) targets=(-target=azurerm_key_vault_key.backup -target=azurerm_role_assignment.mongo_disk_key
                             -target=azurerm_role_assignment.backup_cmk) ;;
    disk-encryption-set) targets=(-target=azurerm_disk_encryption_set.mongo) ;;
    full) ;;
    *) echo 'Unrecognized Terraform target.' >&2; exit 2 ;;
esac
parent="$RUNNER_TEMP/outpost-plans"
install -d -m 0700 "$parent"
private=$(mktemp -d "$parent/run.XXXXXXXX")
trap 'rm -rf -- "$private"' EXIT

if ! terraform -chdir=infra plan -input=false -no-color -lock-timeout=5m \
    "-var=backup_stage=$stage" "${targets[@]}" "-out=$private/saved.tfplan" >"$private/plan.log" 2>&1; then
    echo 'Terraform plan failed. No apply was attempted.' >&2
    python3 infra/pipeline/error_excerpt.py "$private/plan.log"
    exit 1
fi
if ! terraform -chdir=infra show -json "$private/saved.tfplan" 2>"$private/show.log" |
    jq . >"$private/tfplan.json" 2>"$private/json.log"; then
    echo 'Could not decode the saved plan.' >&2
    python3 infra/pipeline/error_excerpt.py "$private/show.log"
    exit 1
fi

scanner=bridgecrew/checkov@sha256:89a4c477508225cdc3ed8a23d15c7e0d9d3029bc8ae192b7f113a6ff5f210c94
status=0
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,nosuid,nodev -e HOME=/tmp -w /tmp \
    -v "$PWD/infra:/source:ro" -v "$private/tfplan.json:/scan/tfplan.json:ro" "$scanner" \
    -f /scan/tfplan.json --framework terraform_plan --repo-root-for-plan-enrichment /source \
    --deep-analysis --skip-download -o json >"$private/checkov.json" 2>"$private/checkov.log" || status=$?
python3 infra/pipeline/plan_gate.py "$private/checkov.json" "$private/tfplan.json" "$status"

if ! terraform -chdir=infra apply -input=false -no-color -lock-timeout=5m \
    "$private/saved.tfplan" >"$private/apply.log" 2>&1; then
    echo 'Terraform failed to apply the scanned plan. Inspect the lab Activity Log before retrying.' >&2
    python3 infra/pipeline/error_excerpt.py "$private/apply.log"
    exit 1
fi
printf 'Applied the scanned %s plan for backup stage %s.\n' "$mode" "$stage"
