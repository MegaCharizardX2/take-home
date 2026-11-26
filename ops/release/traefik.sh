#!/usr/bin/env bash
set -euo pipefail
helm upgrade --install traefik ./traefik.tgz --namespace traefik --skip-crds --wait --timeout 6m --values values.yaml >/dev/null
kubectl -n traefik rollout status deployment/traefik --timeout=60s >/dev/null
[[ $(kubectl get ingressclass traefik -o jsonpath='{.spec.controller}') == traefik.io/ingress-controller ]] || exit 1
[[ $(kubectl -n traefik get service traefik -o jsonpath='{.status.loadBalancer.ingress[0].ip}') == "$(cat frontend-ip)" ]] || exit 1
echo 'traefik ready'
