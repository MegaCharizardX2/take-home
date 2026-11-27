#!/usr/bin/env bash
# Each check exits with its own code (21-30); cluster.py maps it to a fixed label.
set -euo pipefail
kubectl apply --server-side --field-manager=outpost-infra -f namespaces.yaml >/dev/null || exit 21
kubectl apply --server-side --field-manager=outpost-infra -f network.yaml -f identities.yaml -f marker.yaml -f bindings.yaml -f traefik-secret-watch.yaml >/dev/null || exit 22
kubectl get namespace wiz-web wiz-evidence traefik >/dev/null || exit 23
kubectl -n wiz-web get serviceaccount web >/dev/null || exit 23
kubectl -n wiz-evidence get configmap panel-marker >/dev/null || exit 23
phase=$(kubectl -n wiz-evidence get configmap outpost-web-phase --ignore-not-found -o jsonpath='{.data.phase}') || exit 24
if [[ -z $phase ]]; then
    kubectl -n wiz-evidence create configmap outpost-web-phase --from-literal=phase=initializing >/dev/null || exit 24
    phase=initializing
fi
binding=$(kubectl get clusterrolebinding wiz-web-baseline --ignore-not-found -o name) || exit 24
case "$phase" in
    initializing|baseline)
        if [[ -z $binding ]]; then
            # A later setup run must never undo the Outpost revocation.
            [[ $phase == initializing ]] || exit 25
            kubectl create -f baseline-binding.yaml >/dev/null || exit 26
        fi
        actual=$(kubectl get clusterrolebinding wiz-web-baseline -o go-template='{{index .metadata.labels "app.kubernetes.io/part-of"}}|{{.roleRef.apiGroup}}|{{.roleRef.kind}}|{{.roleRef.name}}{{range .subjects}}|{{.kind}}:{{.namespace}}:{{.name}}{{end}}') || exit 27
        [[ $actual == 'outpost|rbac.authorization.k8s.io|ClusterRole|cluster-admin|ServiceAccount:wiz-web:web' ]] || exit 27
        if [[ $phase == initializing ]]; then
            kubectl -n wiz-evidence patch configmap outpost-web-phase --type=json \
                -p='[{"op":"test","path":"/data/phase","value":"initializing"},{"op":"replace","path":"/data/phase","value":"baseline"}]' >/dev/null || exit 28
        fi
        ;;
    outpost) [[ -z $binding ]] || exit 29 ;;
    *) exit 30 ;;
esac
echo 'platform ready'
