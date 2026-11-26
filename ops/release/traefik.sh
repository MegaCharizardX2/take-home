#!/usr/bin/env bash
# Each check exits with its own code (31-34); cluster.py maps it to a fixed label.
set -euo pipefail
helm upgrade --install traefik ./traefik.tgz --namespace traefik --skip-crds --wait --timeout 6m --values values.yaml >/dev/null || exit 31
kubectl -n traefik rollout status deployment/traefik --timeout=60s >/dev/null || exit 32
[[ $(kubectl get ingressclass traefik -o jsonpath='{.spec.controller}') == traefik.io/ingress-controller ]] || exit 33
[[ $(kubectl -n traefik get service traefik -o jsonpath='{.status.loadBalancer.ingress[0].ip}') == "$(cat frontend-ip)" ]] || exit 34
echo 'traefik ready'
