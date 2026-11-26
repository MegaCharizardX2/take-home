#!/usr/bin/env bash
# Each check exits with its own code (81-87); cluster.py maps it to a fixed label.
set -euo pipefail
case $1 in
    image)
        kubectl -n wiz-web rollout status deployment/web --timeout=60s >/dev/null || exit 81
        kubectl -n wiz-web get deployment web -o jsonpath='{.spec.template.spec.containers[?(@.name=="web")].image}' || exit 82
        ;;
    apply)
        kubectl -n wiz-evidence apply -f reader.yaml >/dev/null || exit 83
        kubectl -n wiz-evidence rollout status deployment/backup-reader --timeout=300s >/dev/null || exit 84
        echo 'reader ready'
        ;;
    verify)
        # Only the fixed reader summary can leave the Run Command pod.
        output=$(kubectl -n wiz-evidence exec deployment/backup-reader -c reader -- /app/backup-reader 2>/dev/null | head -c 256 && printf '.') || exit 86
        (( ${#output} <= 256 )) || exit 87
        output=${output%$'\n.'}
        uuid='[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}'
        pattern="^objects ([1-9][0-9]{0,8}) newest ([0-9]{8}T[0-9]{6}Z-${uuid}/dump[.]archive[.]gz) sha256 ([0-9a-f]{64}) endpoint (10[.]84[.]2[.](6[4-9]|[78][0-9]|9[0-5]))$"
        [[ $output =~ $pattern ]] || exit 87
        printf '%s\n' "$output"
        ;;
    *) exit 85 ;;
esac
