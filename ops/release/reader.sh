#!/usr/bin/env bash
# Each check exits with its own code (81-86); cluster.py maps it to a fixed label.
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
        # A fresh one-shot run in the reader pod: workload-identity token, list the
        # container, fetch the newest completed backup and match its SHA-256. The
        # reader refuses any Blob address outside the private-endpoint subnet, so
        # success also proves the path never left the VNet. Its listing stays private.
        kubectl -n wiz-evidence exec deployment/backup-reader -c reader -- /app/backup-reader >/dev/null 2>&1 || exit 86
        echo 'backup verified privately'
        ;;
    *) exit 85 ;;
esac
