#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
private="$RUNNER_TEMP/outpost-images"
install -d -m 0700 "$private"
export DOCKER_CONFIG="$RUNNER_TEMP/outpost-docker"
install -d -m 0700 "$DOCKER_CONFIG"
upstream='busybox:1.38.0-musl@sha256:c9ad541b61c139f331017a452efb032bfd31631602df83de77a73edcb59b0a41'
[[ $GITHUB_SHA =~ ^[0-9a-f]{40}$ ]] || exit 1
case $1 in
    build)
        marker=tasky/wizexercise.txt
        [[ -n $CANDIDATE_NAME && $CANDIDATE_NAME != *$'\n'* && $CANDIDATE_NAME != *$'\r'* ]] || exit 1
        [[ ! -e $marker && ! -L $marker ]] || exit 1
        expected=$(printf '%s\n' "$CANDIDATE_NAME" | sha256sum)
        trap 'rm -f -- "$marker"' EXIT
        printf '%s\n' "$CANDIDATE_NAME" > "$marker"
        unset CANDIDATE_NAME
        docker build --platform linux/amd64 --provenance=false -t "tasky:$GITHUB_SHA" tasky
        rm -f -- "$marker"
        actual=$(docker run --rm --network none --cap-drop ALL --read-only --entrypoint /bin/cat \
            "tasky:$GITHUB_SHA" /app/wizexercise.txt | sha256sum)
        [[ $expected == "$actual" ]] || exit 1
        echo match
        ;;
    scan)
        docker pull --platform linux/amd64 "$upstream"
        docker tag "$upstream" "busybox:$GITHUB_SHA"
        trap 'rm -f -- "$private/image.tar" "$private/scan.json" "$private/scan.log"' EXIT
        for repo in tasky busybox; do
            tag="$repo:$GITHUB_SHA"
            [[ $(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$tag") == linux/amd64 ]] || exit 1
            docker image inspect -f '{{.Id}}' "$tag" > "$private/$repo.id"
            docker save -o "$private/image.tar" "$tag"
            if ! docker run --rm -v "$private/image.tar:/image.tar:ro" "$TRIVY" image --input /image.tar \
                --format json --exit-code 1 --severity UNKNOWN,HIGH,CRITICAL > "$private/scan.json" 2> "$private/scan.log"; then
                echo "Trivy failed for $repo" >&2
                jq -r '.Results[]? | (.Vulnerabilities[]?.VulnerabilityID, .Secrets[]?.RuleID) | select(test("^[A-Za-z0-9_.-]{1,100}$"))' \
                    "$private/scan.json" >&2
                exit 1
            fi
            rm -f -- "$private/image.tar"
        done
        ;;
    push)
        [[ $ACR_LOGIN_SERVER =~ ^acroutpost[0-9a-f]{10}\.azurecr\.io$ ]] || exit 1
        # Exchange an Entra token directly at the registry, without listing registries.
        az account get-access-token --resource https://containerregistry.azure.net --query accessToken -o tsv \
            | tr -d '\r\n' | curl --proto '=https' --silent --fail --max-time 30 \
            --data-urlencode 'grant_type=access_token' --data-urlencode "service=$ACR_LOGIN_SERVER" \
            --data-urlencode "tenant=$ARM_TENANT_ID" --data-urlencode 'access_token@-' \
            "https://$ACR_LOGIN_SERVER/oauth2/exchange" | jq -er '.refresh_token | strings | select(length > 0)' \
            | docker login "$ACR_LOGIN_SERVER" --username 00000000-0000-0000-0000-000000000000 --password-stdin >/dev/null
        for repo in tasky busybox; do
            tag="$ACR_LOGIN_SERVER/$repo:$GITHUB_SHA"
            config=$(cat "$private/$repo.id")
            [[ $config =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
            docker tag "$config" "$tag"
            docker push --platform linux/amd64 "$tag" > "$private/push.log"
            digest=$(sed -nE 's/^[^ ]+: digest: (sha256:[0-9a-f]{64}) size: [0-9]+$/\1/p' "$private/push.log")
            [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
            docker buildx imagetools inspect --raw "$ACR_LOGIN_SERVER/$repo@$digest" | \
                jq -e --arg config "$config" '.schemaVersion == 2 and (.config.digest == $config) and (.layers | type == "array")' >/dev/null
            printf '%s=%s\n%s_config=%s\n' "$repo" "$digest" "$repo" "$config" >> "$GITHUB_OUTPUT"
        done
        printf 'revision=%s\n' "$GITHUB_SHA" >> "$GITHUB_OUTPUT"
        ;;
    *) exit 2 ;;
esac
