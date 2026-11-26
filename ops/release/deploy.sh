#!/usr/bin/env bash
set -euo pipefail
kubectl -n wiz-web --request-timeout=60s apply --server-side --dry-run=server --field-manager=outpost-release -f deploy.yaml >/dev/null
kubectl -n wiz-web --request-timeout=60s apply --server-side --field-manager=outpost-release -f deploy.yaml >/dev/null
kubectl -n wiz-web rollout status deployment/web --timeout=360s >/dev/null
echo 'rollout ready'
