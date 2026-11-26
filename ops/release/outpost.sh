#!/usr/bin/env bash
# Outpost web identity transition, attached to the AKS Run Command pod.
# One Ready web pod is observed for the whole step: its own service-account token
# asks the API server whether it may read wiz-evidence/panel-marker before and
# after the cluster-admin binding is deleted. Expected first run: allowed -> denied
# on the same pod UID. Reruns are safe and report the current decision.
# Each check exits with its own code (101-111); cluster.py maps it to a fixed label.
set -euo pipefail
k=(kubectl -n wiz-web)

phase=$(kubectl -n wiz-evidence get configmap outpost-web-phase -o jsonpath='{.data.phase}') || exit 101
case "$phase" in baseline|outpost) ;; *) exit 102 ;; esac
binding=$(kubectl get clusterrolebinding wiz-web-baseline --ignore-not-found -o name) || exit 103
[[ $phase == baseline || -z $binding ]] || exit 111

pods=$("${k[@]}" get pods -l app=web -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{.metadata.uid}{"|"}{.metadata.deletionTimestamp}{"|"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}') || exit 104
pod='' uid=''
while IFS='|' read -r name id deleting ready; do
    if [[ -z $deleting && $ready == True && $name =~ ^web-[a-z0-9]+-[a-z0-9]+$ && $id =~ ^[a-f0-9-]{36}$ ]]; then
        pod=$name uid=$id
        break
    fi
done <<< "$pods"
[[ -n $pod ]] || exit 104
# A projected serviceAccountToken source means the pod carries an API credential.
projected=$("${k[@]}" get pod "$pod" -o jsonpath='{range .spec.volumes[*]}{.projected.sources[*].serviceAccountToken.path}{end}') || exit 104

# Print allowed, denied or absent. The fixed-purpose checker prints only the
# decision and exits 2 when it has no token (or the review fails).
observe() {
    local out rc=0
    out=$("${k[@]}" exec "$pod" -c web -- /app/check-panel-marker-access 2>/dev/null) || rc=$?
    if [[ -n $projected ]]; then
        [[ $rc == 0 && ( $out == allowed || $out == denied ) ]] || return 1
        echo "$out"
    else
        [[ $rc == 2 && -z $out ]] || return 1
        echo absent
    fi
}

before=$(observe) || exit 105
if [[ -n $binding ]]; then
    kubectl delete clusterrolebinding wiz-web-baseline --ignore-not-found >/dev/null || exit 106
fi
remaining=$(kubectl get clusterrolebinding wiz-web-baseline --ignore-not-found -o name) || exit 103
[[ -z $remaining ]] || exit 107
# RBAC changes reach the authorizer within seconds; allow up to a minute.
after=allowed
for ((attempt = 0; attempt < 20; attempt++)); do
    after=$(observe) || exit 105
    [[ $after == allowed ]] || break
    sleep 3
done
[[ $after != allowed ]] || exit 108
# The proof only counts if the same pod answered both times.
now=$("${k[@]}" get pod "$pod" -o jsonpath='{.metadata.uid}{"|"}{.metadata.deletionTimestamp}') || exit 109
[[ $now == "$uid|" ]] || exit 109
if [[ $phase == baseline ]]; then
    kubectl -n wiz-evidence patch configmap outpost-web-phase --type=json \
        -p='[{"op":"test","path":"/data/phase","value":"baseline"},{"op":"replace","path":"/data/phase","value":"outpost"}]' >/dev/null || exit 110
fi
printf 'pod %s %s\nbefore %s\nafter %s\nphase outpost\n' "$pod" "$uid" "$before" "$after"
