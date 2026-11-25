#!/usr/bin/env bash
set -euo pipefail
kubectl apply --server-side --field-manager=outpost-infra -f namespaces.yaml >/dev/null
kubectl apply --server-side --field-manager=outpost-infra -f network.yaml -f identities.yaml -f marker.yaml -f bindings.yaml -f traefik-secret-watch.yaml >/dev/null
kubectl get namespace wiz-web wiz-evidence traefik >/dev/null
kubectl -n wiz-web get serviceaccount web >/dev/null
kubectl -n wiz-evidence get configmap panel-marker >/dev/null
phase=$(kubectl -n wiz-evidence get configmap outpost-web-phase --ignore-not-found -o jsonpath='{.data.phase}')
if [[ -z $phase ]]; then
    kubectl -n wiz-evidence create configmap outpost-web-phase --from-literal=phase=initializing >/dev/null
    phase=initializing
fi
binding=$(kubectl get clusterrolebinding wiz-web-baseline --ignore-not-found -o name)
case "$phase" in
    initializing|baseline)
        if [[ -z $binding ]]; then
            # A later setup run must never undo the Outpost revocation.
            [[ $phase == initializing ]] || exit 1
            kubectl create -f baseline-binding.yaml >/dev/null
        fi
        actual=$(kubectl get clusterrolebinding wiz-web-baseline -o go-template='{{index .metadata.labels "app.kubernetes.io/part-of"}}|{{.roleRef.apiGroup}}|{{.roleRef.kind}}|{{.roleRef.name}}{{range .subjects}}|{{.kind}}:{{.namespace}}:{{.name}}{{end}}')
        [[ $actual == 'outpost|rbac.authorization.k8s.io|ClusterRole|cluster-admin|ServiceAccount:wiz-web:web' ]] || exit 1
        if [[ $phase == initializing ]]; then
            kubectl -n wiz-evidence patch configmap outpost-web-phase --type=json \
                -p='[{"op":"test","path":"/data/phase","value":"initializing"},{"op":"replace","path":"/data/phase","value":"baseline"}]' >/dev/null
        fi
        ;;
    outpost) [[ -z $binding ]] || exit 1 ;;
    *) exit 1 ;;
esac
echo 'platform ready'
