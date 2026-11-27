#!/usr/bin/env bash
# Each check exits with its own code (20-30); cluster.py maps it to a fixed label.
# The repository no longer carries the Phase-1 cluster-admin binding: setup never
# grants it, and only `cluster.py outpost` (outpost.sh) revokes a live one.
set -euo pipefail
kubectl apply --server-side --field-manager=outpost-infra -f namespaces.yaml >/dev/null || exit 21
phase=$(kubectl -n wiz-evidence get configmap outpost-web-phase --ignore-not-found -o jsonpath='{.data.phase}') || exit 24
binding=$(kubectl get clusterrolebinding wiz-web-baseline --ignore-not-found -o name) || exit 24
if [[ $phase == baseline ]]; then
    # network.yaml no longer routes web pods to the API. Until outpost.sh has proved
    # the revocation on a running pod, that route lives only in its own policy.
    kubectl apply --server-side --field-manager=outpost-infra -f web-api-transition.yaml >/dev/null || exit 27
fi
kubectl apply --server-side --field-manager=outpost-infra -f network.yaml -f identities.yaml -f marker.yaml -f bindings.yaml -f traefik-secret-watch.yaml >/dev/null || exit 22
kubectl get namespace wiz-web wiz-evidence traefik >/dev/null || exit 23
kubectl -n wiz-web get serviceaccount web >/dev/null || exit 23
kubectl -n wiz-evidence get configmap panel-marker >/dev/null || exit 23
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
if [[ $phase != baseline ]]; then
    # Outpost phase: web pods have no token and no route to the API. Never reopen it.
    kubectl -n wiz-web delete networkpolicy tasky-api-transition --ignore-not-found >/dev/null || exit 20
    left=$(kubectl -n wiz-web get networkpolicy tasky-api-transition --ignore-not-found -o name) || exit 20
    [[ -z $left ]] || exit 20
fi
echo 'platform ready'
