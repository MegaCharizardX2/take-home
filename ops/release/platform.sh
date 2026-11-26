#!/usr/bin/env bash
# Each check exits with its own code (21-30); cluster.py maps it to a fixed label.
# The repository no longer carries the Phase-1 cluster-admin binding: setup never
# grants it, and only `cluster.py outpost` (outpost.sh) revokes a live one.
set -euo pipefail
kubectl apply --server-side --field-manager=outpost-infra -f namespaces.yaml >/dev/null || exit 21
kubectl apply --server-side --field-manager=outpost-infra -f network.yaml -f identities.yaml -f marker.yaml -f bindings.yaml -f traefik-secret-watch.yaml >/dev/null || exit 22
kubectl get namespace wiz-web wiz-evidence traefik >/dev/null || exit 23
kubectl -n wiz-web get serviceaccount web >/dev/null || exit 23
kubectl -n wiz-evidence get configmap panel-marker >/dev/null || exit 23
phase=$(kubectl -n wiz-evidence get configmap outpost-web-phase --ignore-not-found -o jsonpath='{.data.phase}') || exit 24
binding=$(kubectl get clusterrolebinding wiz-web-baseline --ignore-not-found -o name) || exit 24
case "$phase" in
    '')
        # A cluster built from the hardened code starts in the Outpost phase.
        [[ -z $binding ]] || exit 25
        kubectl -n wiz-evidence create configmap outpost-web-phase --from-literal=phase=outpost >/dev/null || exit 26
        ;;
    initializing)
        [[ -z $binding ]] || exit 25
        kubectl -n wiz-evidence patch configmap outpost-web-phase --type=json \
            -p='[{"op":"test","path":"/data/phase","value":"initializing"},{"op":"replace","path":"/data/phase","value":"outpost"}]' >/dev/null || exit 28
        ;;
    # The live Phase-1 binding stays until the outpost step records the same-pod proof.
    baseline) ;;
    outpost) [[ -z $binding ]] || exit 29 ;;
    *) exit 30 ;;
esac
echo 'platform ready'
