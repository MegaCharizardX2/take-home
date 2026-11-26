#!/usr/bin/env bash
# Each check exits with its own code (81-85); cluster.py maps it to a fixed label.
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
    *) exit 85 ;;
esac
