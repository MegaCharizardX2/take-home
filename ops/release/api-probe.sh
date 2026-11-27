#!/usr/bin/env bash
set -euo pipefail
pods=$(kubectl -n kube-system get pods -o name) || exit 117
[[ -n $pods ]] || exit 117
kubectl -n wiz-web exec deployment/web -c web -- /bin/busybox true >/dev/null || exit 118
echo 'kube-system pods listed and web exec succeeded'
