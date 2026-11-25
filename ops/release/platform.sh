#!/usr/bin/env bash
set -euo pipefail
kubectl apply -f namespaces.yaml >/dev/null
kubectl apply -f identities.yaml -f marker.yaml -f network.yaml >/dev/null
kubectl get namespace wiz-web wiz-evidence traefik >/dev/null
kubectl -n wiz-web get serviceaccount web >/dev/null
kubectl -n wiz-evidence get configmap panel-marker >/dev/null
echo 'platform ready'
