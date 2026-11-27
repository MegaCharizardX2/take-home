#!/usr/bin/env bash
# Each check exits with its own code (41, 43, 44); cluster.py maps it to a fixed label.
set -euo pipefail
kubectl -n wiz-web --request-timeout=60s apply --server-side --dry-run=server --field-manager=outpost-release -f deploy.yaml >/dev/null || exit 41
kubectl -n wiz-web --request-timeout=60s apply --server-side --field-manager=outpost-release -f deploy.yaml >/dev/null || exit 43
kubectl -n wiz-web rollout status deployment/web --timeout=360s >/dev/null || exit 44
echo 'rollout ready'
