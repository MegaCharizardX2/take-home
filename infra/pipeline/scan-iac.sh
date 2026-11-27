#!/usr/bin/env bash
# Run from the repository root, with the same expiring policy used in CI.
set -euo pipefail
umask 077
policy=$(mktemp -d "$PWD/.scan-policy.XXXXXXXX")
trap 'rm -rf -- "$policy"' EXIT
for config in checkov.yaml trivy.yaml public-access.tf; do
    python3 infra/pipeline/scanner_policy.py "$config" >"$policy/$config"
done

checkov=bridgecrew/checkov@sha256:89a4c477508225cdc3ed8a23d15c7e0d9d3029bc8ae192b7f113a6ff5f210c94
trivy=aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
mounts=(-v "$PWD:/src:ro" -v "$policy:/policy:ro" -w /src)
for dir in infra k8s tasky; do
    case "$dir" in
        tasky) frameworks=(dockerfile) ;;
        *) frameworks=(terraform kubernetes) ;;
    esac
    docker run --rm "${mounts[@]}" "$checkov" --skip-download -d "$dir" --config-file /policy/checkov.yaml --framework "${frameworks[@]}"
    docker run --rm "${mounts[@]}" -v "$policy/public-access.tf:/src/infra/public-access.tf:ro" "$trivy" config --skip-check-update --ignorefile /policy/trivy.yaml --exit-code 1 --severity UNKNOWN,HIGH,CRITICAL "$dir"
done
