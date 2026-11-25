#!/usr/bin/env bash
# Keep ARM's logs to validated object identifiers and a fixed marker result.
set +x
set -euo pipefail
exec 2>/dev/null
read -r app init revision < images.txt
k=(kubectl -n wiz-web)
node=$(kubectl get nodes -l workload=web -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
[[ $node =~ ^[a-z0-9][a-z0-9.-]{0,252}$ ]] || exit 1
node_facts=$(kubectl get node "$node" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}{" "}{.metadata.uid}{" "}{range .spec.taints[*]}{.key}={.value}:{.effect}{","}{end}')
read -r ready node_uid taints <<< "$node_facts"
[[ $ready == True && $node_uid =~ ^[a-f0-9-]{36}$ && ,$taints == *,workload=web:NoSchedule,* ]] || exit 1
state=$("${k[@]}" get deploy web -o jsonpath='{.metadata.uid}{" "}{.metadata.generation}{" "}{.status.observedGeneration}{" "}{.spec.replicas}{" "}{.status.replicas}{" "}{.status.updatedReplicas}{" "}{.status.readyReplicas}{" "}{.status.availableReplicas}{" "}{.metadata.annotations.deployment\.kubernetes\.io/revision}{" "}{.spec.template.spec.containers[?(@.name=="web")].image}{" "}{.spec.template.spec.initContainers[?(@.name=="wait-mongo")].image}{" "}{.spec.template.metadata.annotations.outpost\.wiz/revision}')
read -r uid generation observed desired replicas updated ready available version web_image init_image sha <<< "$state"
[[ $uid =~ ^[a-f0-9-]{36}$ && $generation =~ ^[1-9][0-9]*$ && $generation == "$observed" && $version =~ ^[1-9][0-9]*$ ]] || exit 1
[[ $desired:$replicas:$updated:$ready:$available == 2:2:2:2:2 && $web_image == "$app" && $init_image == "$init" && $sha == "$revision" ]] || exit 1
sets=$("${k[@]}" get rs -l app=web -o jsonpath='{range .items[*]}{.metadata.uid}{" "}{.metadata.ownerReferences[?(@.controller==true)].uid}{" "}{.metadata.annotations.deployment\.kubernetes\.io/revision}{"\n"}{end}')
current=$(awk -v owner="$uid" -v rev="$version" '$2 == owner && $3 == rev {print $1}' <<< "$sets")
[[ $current =~ ^[a-f0-9-]{36}$ ]] || exit 1
pods=$("${k[@]}" get pods -l app=web -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{.metadata.deletionTimestamp}{"|"}{.metadata.ownerReferences[?(@.controller==true)].uid}{"|"}{.status.conditions[?(@.type=="Ready")].status}{"|"}{.spec.nodeName}{"|"}{.spec.nodeSelector.workload}{"|"}{.spec.containers[?(@.name=="web")].image}{"|"}{.spec.initContainers[?(@.name=="wait-mongo")].image}{"|"}{range .spec.tolerations[*]}{.key}:{.operator}:{.value}:{.effect}{","}{end}{"\n"}{end}')
verified=()
while IFS='|' read -r pod deleting owner ready placement selector image init_image tolerations; do
    [[ -z $deleting ]] || continue
    [[ $pod =~ ^web-[a-z0-9]+-[a-z0-9]+$ && $owner == "$current" && $ready == True ]] || exit 1
    [[ $placement == "$node" && $selector == web && $image == "$app" && $init_image == "$init" ]] || exit 1
    [[ ,$tolerations == *,workload:Equal:web:NoSchedule,* ]] || exit 1
    actual=$("${k[@]}" exec "$pod" -c web -- cat /app/wizexercise.txt | sha256sum)
    [[ ${actual%% *} == "$(cat expected)" ]] || exit 1
    verified+=("$pod")
done <<< "$pods"
[[ ${#verified[@]} == 2 && ${verified[0]} != "${verified[1]}" ]] || exit 1
printf 'node %s %s\npod %s\npod %s\nmatch\n' "$node" "$node_uid" "${verified[0]}" "${verified[1]}"
