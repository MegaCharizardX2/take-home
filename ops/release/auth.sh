#!/usr/bin/env bash
set -euo pipefail
# ARM Run Command must preserve the intended caller in the cluster.
# Each check exits with its own code (11-19) so the runner can say which one failed
# without printing any Kubernetes output. 42 = unexpected principal.
read -r principal client mode < auth.txt
username=$(kubectl auth whoami -o jsonpath='{.status.userInfo.username}')
case "$(tr '[:upper:]' '[:lower:]' <<< "$username")" in
    "$principal"|"$client"|"spn:$principal"|"spn:$client") ;;
    *) exit 42 ;;
esac
if [[ $mode == infra ]]; then
    [[ $(kubectl auth can-i create namespaces) == yes ]] || exit 11
    [[ $(kubectl auth can-i create clusterrolebindings.rbac.authorization.k8s.io) == yes ]] || exit 12
else
    [[ $mode == release ]] || exit 13
    [[ $(kubectl auth can-i patch deployments.apps -n wiz-web) == yes ]] || exit 14
    [[ $(kubectl auth can-i list nodes) == yes ]] || exit 15
    # A denial can include an authorizer reason. Only the decision and evaluation error matter.
    decision=$(kubectl create -f - -o 'jsonpath={.status.allowed}{"|"}{.status.evaluationError}{"|"}' <<'JSON'
{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"namespace":"wiz-evidence","verb":"create","group":"","resource":"configmaps"}}}
JSON
    ) || exit 16
    [[ $decision == 'false||' ]] || exit 17
    if message=$(kubectl -n wiz-evidence create configmap outpost-release-boundary-check \
        --from-literal=marker=synthetic --dry-run=server -o name 2>&1); then exit 18; fi
    [[ $message == *'(Forbidden)'* && $message == *'cannot create resource "configmaps"'* \
       && $message == *'in the namespace "wiz-evidence"'* ]] || exit 19
fi
