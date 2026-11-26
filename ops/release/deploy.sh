#!/usr/bin/env bash
# Each check exits with its own code (41, 43-46); cluster.py maps it to a fixed label.
set -euo pipefail
k=(kubectl -n wiz-web --request-timeout=60s)
# Outpost order: the token-free release must not replace the pod that proves the
# revocation. While a running web pod's own token is still allowed to read the
# panel marker, the cluster-admin binding is live: run cluster setup outpost first.
pods=$("${k[@]}" get pods -l app=web -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{.metadata.deletionTimestamp}{"|"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}') || exit 46
while IFS='|' read -r pod deleting ready; do
    [[ -z $deleting && $ready == True && $pod =~ ^web-[a-z0-9]+-[a-z0-9]+$ ]] || continue
    decision=$("${k[@]}" exec "$pod" -c web -- /app/check-panel-marker-access 2>/dev/null) || decision=''
    [[ $decision != allowed ]] || exit 45
done <<< "$pods"
"${k[@]}" apply --server-side --dry-run=server --field-manager=outpost-release -f deploy.yaml >/dev/null || exit 41
"${k[@]}" apply --server-side --field-manager=outpost-release -f deploy.yaml >/dev/null || exit 43
kubectl -n wiz-web rollout status deployment/web --timeout=360s >/dev/null || exit 44
echo 'rollout ready'
