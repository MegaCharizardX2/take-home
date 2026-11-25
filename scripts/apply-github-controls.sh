#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  '') apply=true ;;
  --check) apply=false ;;
  *) echo "Usage: $0 [--check]" >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.."
repo=repos/MegaCharizardX2/take-home
rules=.github/rulesets/main-protection.json
get() { gh api "$repo${1:+/$1}"; }
write() {
  if "$apply"; then
    printf '%s' "$3" | gh api --silent -X "$1" "$repo${2:+/$2}" --input -
  fi
}
verify() { get "$1" | jq -e "$2" >/dev/null || { echo "Drift: $1 $2" >&2; exit 1; }; }
verify '' '.default_branch == "main" and .visibility == "public"'
verify collaborators/msftnadavbh/permission '.user.permissions.push == true'
# Require a successful bootstrap CI run on the current main commit.
head_sha=$(get git/ref/heads/main | jq -r .object.sha)
run_id=$(get "actions/workflows/ci.yml/runs?branch=main&event=push&status=success&head_sha=$head_sha" | jq -er '.workflow_runs[0].id')
jobs=$(get "actions/runs/$run_id/jobs" | jq -c '[.jobs[] | select(.conclusion=="success") | .name]')
jq -e --argjson jobs "$jobs" '([.rules[].parameters.required_status_checks[]?.context] - $jobs) == []' "$rules" >/dev/null

security='{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}'
merge='{"allow_squash_merge":true,"allow_merge_commit":false,"allow_rebase_merge":false,"delete_branch_on_merge":true,"allow_auto_merge":false}'
write PATCH '' "$(jq -nc --argjson m "$merge" --argjson s "$security" '$m + {security_and_analysis:$s}')"
verify '' "contains($merge) and (.security_and_analysis | contains($security))"
for flag in vulnerability-alerts automated-security-fixes private-vulnerability-reporting; do
  write PUT "$flag" '{}'
done
get vulnerability-alerts >/dev/null
verify automated-security-fixes '.enabled == true'
verify private-vulnerability-reporting '.enabled == true'

policy() {
  write PUT "$1" "$2"
  verify "$1" "contains($2)"
}
policy actions/permissions '{"enabled":true,"allowed_actions":"selected","sha_pinning_required":true}'
allowed='{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["hashicorp/setup-terraform@dfe3c3f87815947d99a8997f908cb6525fc44e9e","terraform-linters/setup-tflint@6ffdbaa3be476b3431f7275c26966ef32ff60337"]}'
policy actions/permissions/selected-actions "$allowed"
verify actions/permissions/selected-actions "(.patterns_allowed|sort) == ($allowed.patterns_allowed|sort)"
policy actions/permissions/workflow '{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}'
policy actions/permissions/fork-pr-contributor-approval '{"approval_policy":"all_external_contributors"}'

reviewer=$(gh api users/msftnadavbh --jq .id)
for env in infra release; do
  path=environments/$env
  write PUT "$path" "{\"prevent_self_review\":true,\"reviewers\":[{\"type\":\"User\",\"id\":$reviewer}],\"deployment_branch_policy\":{\"protected_branches\":false,\"custom_branch_policies\":true}}"
  verify "$path" ".deployment_branch_policy == {protected_branches:false,custom_branch_policies:true} and ([.protection_rules[] | select(.type==\"required_reviewers\") | [.prevent_self_review, [.reviewers[].reviewer.id]]] == [[true,[$reviewer]]])"
  path=$path/deployment-branch-policies
  if [[ $(get "$path" | jq '.total_count') == 0 ]]; then
    write POST "$path" '{"name":"main","type":"branch"}'
  fi
  verify "$path" '.total_count == 1 and .branch_policies[0].name == "main" and .branch_policies[0].type == "branch"'
done

# Activate branch protection only after all preceding checks succeed.
id=$(get 'rulesets?includes_parents=false' | jq -r '.[] | select(.name=="main-protection") | .id')
if [[ -n "$id" ]]; then
  write PUT "rulesets/$id" "$(cat "$rules")"
else
  write POST rulesets "$(cat "$rules")"
  id=$(get rulesets | jq -er '.[] | select(.name=="main-protection") | .id')
fi
get "rulesets/$id" | jq -e --slurpfile spec "$rules" '
  contains($spec[0]) and .bypass_actors == [] and .conditions == $spec[0].conditions and
  ([.rules[].type]|sort) == ([$spec[0].rules[].type]|sort) and
  ([.rules[].parameters.required_status_checks[]?.context]|sort) == ([$spec[0].rules[].parameters.required_status_checks[]?.context]|sort)' >/dev/null
echo "Verified repository controls and main-protection ruleset $id"
