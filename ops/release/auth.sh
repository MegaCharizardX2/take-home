#!/usr/bin/env bash
set -euo pipefail
# ARM Run Command must preserve the intended caller in the cluster.
read -r principal client mode < auth.txt
username=$(kubectl auth whoami -o jsonpath='{.status.userInfo.username}')
case "$(tr '[:upper:]' '[:lower:]' <<< "$username")" in
    "$principal"|"$client"|"spn:$principal"|"spn:$client") ;;
    *) exit 42 ;;
esac
if [[ $mode == infra ]]; then
    [[ $(kubectl auth can-i create namespaces) == yes ]] || exit 1
    [[ $(kubectl auth can-i create clusterrolebindings.rbac.authorization.k8s.io) == yes ]] || exit 1
else
    [[ $mode == release ]] || exit 1
    [[ $(kubectl auth can-i patch deployments.apps -n wiz-web) == yes ]] || exit 1
    [[ $(kubectl auth can-i list nodes) == yes ]] || exit 1
    denial=0
    evidence=$(kubectl auth can-i create configmaps -n wiz-evidence) || denial=$?
    [[ $denial == 1 && $evidence == no ]] || exit 1
fi
