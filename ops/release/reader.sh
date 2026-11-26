#!/usr/bin/env bash
set -euo pipefail
case $1 in
    image)
        kubectl -n wiz-web rollout status deployment/web --timeout=60s >/dev/null
        kubectl -n wiz-web get deployment web -o jsonpath='{.spec.template.spec.containers[?(@.name=="web")].image}'
        ;;
    apply)
        kubectl -n wiz-evidence apply -f reader.yaml >/dev/null
        kubectl -n wiz-evidence rollout status deployment/backup-reader --timeout=300s >/dev/null
        echo 'reader ready'
        ;;
    *) exit 2 ;;
esac
