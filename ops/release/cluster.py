"""Protected workflow steps. Only allowlisted evidence leaves the runner's private directory."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'ops/release'
UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
DIGEST = r'sha256:[a-f0-9]{64}'
REGISTRY = r'acroutpost[0-9a-f]{10}\.azurecr\.io'
FQDN = r'outpost-[0-9a-f]{10}(?:\.[a-z0-9-]{1,63})?\.eastus2\.cloudapp\.azure\.com'
ACR_PLACEHOLDER = 'registry.invalid/{}@sha256:' + '0' * 64
TRAEFIK_SHA = '29cbf019c5e013d9455c89fa29be66d2dd9007c84ed51b969220225fd1b7983c'
TRAEFIK_URL = 'https://traefik.github.io/charts/traefik/traefik-43.0.0.tgz'
CHECKOV = 'bridgecrew/checkov@sha256:89a4c477508225cdc3ed8a23d15c7e0d9d3029bc8ae192b7f113a6ff5f210c94'


class Failure(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Failure(reason)


def checked(value, pattern, label):
    require(isinstance(value, str) and re.fullmatch(pattern, value), 'Invalid ' + label)
    return value


def env(key, pattern):
    return checked(os.environ.get(key), pattern, key)


def run(args, *, cwd=None, timeout=90):
    # Tool errors may include attachment contents, bearer credentials or an invalid manifest.
    try:
        result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure('Tool unavailable or deadline exceeded') from None
    require(result.returncode == 0, 'External command failed')
    return result.stdout


def arm(*args):
    return run(['az', *args, '--subscription', env('ARM_SUBSCRIPTION_ID', UUID), '--only-show-errors', '-o', 'tsv']).decode().strip()


def write(path, value):
    path.write_text(value, encoding='utf-8')
    path.chmod(0o600)


def copy(path, target):
    write(target, path.read_text())


def record(line):
    print(line, flush=True)
    if 'GITHUB_STEP_SUMMARY' in os.environ:
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as summary:
            print(line, file=summary)
            print(file=summary)


def result(reply, *, principal_gate=False):
    doc = json.loads(reply)
    require(isinstance(doc, dict) and doc.get('provisioningState') == 'Succeeded', 'ARM operation failed')
    code = doc.get('exitCode')
    if principal_gate and type(code) is int and code == 42:
        raise Failure('Unexpected Kubernetes principal')
    require(type(code) is int and code == 0, 'Missing or unsuccessful remote exit code')
    # Azure CLI returns commandResults.name as id or a full ARM resource ID.
    prefix = r'/subscriptions/' + UUID + r'/resourceGroups/takehome-rg/providers/Microsoft\.ContainerService/managedClusters/aks-outpost/commandResults/'
    request = checked(doc.get('id'), rf'(?i)(?:{prefix})?(?:[0-9a-f]{{32}}|{UUID})', 'AKS request ID')
    require(isinstance(doc.get('logs'), str), 'Missing AKS command logs')
    return request, doc['logs'].strip()


def invoke(work, command, files, *, timeout=390, principal_gate=False):
    args = ['az', 'aks', 'command', 'invoke', '-g', 'takehome-rg', '-n', 'aks-outpost',
            '--subscription', env('ARM_SUBSCRIPTION_ID', UUID), '--only-show-errors', '-o', 'json']
    for name in files:
        require(Path(name).name == name and (work / name).is_file(), 'Missing AKS attachment')
        args += ['--file', name]
    return result(run(args + ['--command', command], timeout=timeout, cwd=work), principal_gate=principal_gate)


def fixed(work, command, files, proof, **kwargs):
    request, logs = invoke(work, command, files, **kwargs)
    require(logs == proof, 'Missing expected Kubernetes result')
    record(f'{proof} · AKS request `{request}`')


def gate(work, mode):
    deadline = time.monotonic() + 900
    client = env('ARM_CLIENT_ID', UUID)
    if mode == 'infra':
        group = ['-g', 'takehome-rg']
        aks = arm('aks', 'show', *group, '-n', 'aks-outpost', '--query', '[provisioningState,powerState.code]')
        vm = arm('vm', 'get-instance-view', *group, '-n', 'vm-mongo', '--query', "instanceView.statuses[?code=='PowerState/running'].code | [0]")
        require(aks.split() == ['Succeeded', 'Running'] and vm == 'PowerState/running', 'Database VM or AKS unavailable')
        principal = checked(arm('identity', 'show', *group, '-n', 'takehome-id', '--query', 'principalId'), UUID, 'infra principal')
    else:
        principal = env('RELEASE_PRINCIPAL_ID', UUID)
    write(work / 'auth.txt', f'{principal} {client} {mode}\n')
    copy(SCRIPTS / 'auth.sh', work / 'auth.sh')
    last = 'Authorization gate delayed'
    delay = 15
    while time.monotonic() < deadline:
        try:
            fixed(work, "bash auth.sh 2>/dev/null && echo authorized", ['auth.txt', 'auth.sh'], 'authorized',
                  timeout=min(120, max(1, deadline - time.monotonic())), principal_gate=True)
            return
        except Failure as error:
            if str(error) == 'Unexpected Kubernetes principal' or mode == 'release':
                raise
            last = str(error)
        time.sleep(max(0, min(delay, deadline - time.monotonic())))
        delay = min(2 * delay, 60)
    raise Failure('Authorization deadline exceeded: ' + last)


def ingress():
    fqdn = checked(arm('network', 'public-ip', 'show', '-g', 'takehome-rg', '-n', 'pip-ingress', '--query', 'dnsSettings.fqdn'), FQDN, 'ingress FQDN')
    return fqdn, fqdn.split('.')[0].removeprefix('outpost-')


def substitute(text, placeholder, replacement):
    require(placeholder in text, 'Expected template placeholder missing')
    return text.replace(placeholder, replacement)


def setup(work):
    fqdn, suffix = ingress()
    account = checked('stoutpost' + suffix, r'stoutpost[0-9a-f]{10}', 'backup account')
    require(arm('storage', 'account', 'show', '-g', 'takehome-rg', '-n', account, '--query', 'name') == account, 'Backup account mismatch')
    reader_id = checked(arm('identity', 'show', '-g', 'takehome-rg', '-n', 'id-backup-reader', '--query', 'clientId'), UUID, 'reader client ID')
    for name in ('namespaces', 'identities', 'marker', 'network'):
        source = (ROOT / f'k8s/platform/{name}.yaml').read_text()
        if name == 'identities':
            source = substitute(source, '00000000-0000-0000-0000-000000000000', reader_id)
        write(work / f'{name}.yaml', source)
    copy(SCRIPTS / 'platform.sh', work / 'platform.sh')
    fixed(work, 'bash platform.sh 2>/dev/null', ['platform.sh', 'namespaces.yaml', 'identities.yaml', 'marker.yaml', 'network.yaml'], 'platform ready')
    lock = json.loads((ROOT / 'ops/traefik/chart.lock').read_text())
    require(lock.get('version') in ('43.0.0', 'v43.0.0') and lock.get('sha256') == TRAEFIK_SHA and lock.get('url') == TRAEFIK_URL, 'Unexpected Traefik chart lock')
    chart = run(['curl', '--proto', '=https', '--proto-redir', '=https', '--location', '--fail', '--silent', '--max-time', '60', TRAEFIK_URL])
    require(hashlib.sha256(chart).hexdigest() == TRAEFIK_SHA, 'Traefik chart verification failed')
    (work / 'traefik.tgz').write_bytes(chart)
    values = (ROOT / 'ops/traefik/values.yaml').read_text()
    write(work / 'values.yaml', substitute(values, 'tasky.invalid', fqdn))
    copy(SCRIPTS / 'traefik.sh', work / 'traefik.sh')
    fixed(work, 'bash traefik.sh 2>/dev/null', ['traefik.sh', 'values.yaml', 'traefik.tgz'], 'traefik ready', timeout=570)


def secret(work):
    uri = os.environ.pop('MONGODB_URI', '')
    key = os.environ.pop('SECRET_KEY', '')
    checked(uri, r'mongodb://tasky:[0-9a-fA-F]+@mongo\.wiz\.internal:27017/\?authSource=admin', 'MongoDB URI')
    require(len(key.encode()) >= 32, 'JWT key is too short')
    manifest = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'namespace': 'wiz-web', 'name': 'tasky-config'},
                'type': 'Opaque', 'data': {k: base64.b64encode(v.encode()).decode('ascii') for k, v in [('MONGODB_URI', uri), ('SECRET_KEY', key)]}}
    file = work / 'secret.json'
    try:
        write(file, json.dumps(manifest))
        # A Go template checks both keys inside kubectl without emitting their values.
        command = ("kubectl -n wiz-web apply --server-side --field-manager=outpost-infra -f secret.json >/dev/null 2>&1 && "
                   "kubectl -n wiz-web get secret tasky-config -o go-template='{{if and (index .data \"MONGODB_URI\") (index .data \"SECRET_KEY\")}}secret ready{{end}}' 2>/dev/null")
        fixed(work, command, [file.name], 'secret ready')
    finally:
        file.unlink(missing_ok=True)


def reader(work):
    _, suffix = ingress()
    registry = checked(f'acroutpost{suffix}.azurecr.io', REGISTRY, 'registry')
    require(arm('acr', 'show', '-g', 'takehome-rg', '-n', registry.split('.')[0], '--query', 'loginServer') == registry, 'Registry mismatch')
    copy(SCRIPTS / 'reader.sh', work / 'reader.sh')
    request, image = invoke(work, 'bash reader.sh image 2>/dev/null', ['reader.sh'])
    checked(image, re.escape(registry) + '/tasky@' + DIGEST, 'live web image')
    record(f'Current web image verified · AKS request `{request}`')
    template = (ROOT / 'k8s/reader/deployment.yaml').read_text()
    template = substitute(template, ACR_PLACEHOLDER.format('tasky'), image)
    write(work / 'reader.yaml', substitute(template, 'stoutpost0000000000', 'stoutpost' + suffix))
    fixed(work, 'bash reader.sh apply 2>/dev/null', ['reader.sh', 'reader.yaml'], 'reader ready')


def release():
    registry = env('ACR_LOGIN_SERVER', REGISTRY)
    sha = env('REVISION', r'[0-9a-f]{40}')
    require(sha == os.environ.get('GITHUB_SHA'), 'Published revision differs from workflow checkout')
    return sha, {repo: f'{registry}/{repo}@' + env(f'{repo.upper()}_DIGEST', DIGEST) for repo in ('tasky', 'busybox')}


def render(work):
    sha, images = release()
    fqdn = env('INGRESS_FQDN', FQDN)
    require(fqdn.split('.')[0].removeprefix('outpost-') == env('ACR_LOGIN_SERVER', REGISTRY).split('.')[0].removeprefix('acroutpost'), 'Registry and ingress belong to different instances')
    manifests = []
    for name in ('deployment', 'service', 'ingress'):
        template = (ROOT / f'k8s/web/{name}.yaml').read_text()
        if name == 'deployment':
            for repo, image in images.items():
                template = substitute(template, ACR_PLACEHOLDER.format(repo), image)
            template = substitute(template, 'outpost.wiz/revision: "' + '0' * 40 + '"', f'outpost.wiz/revision: "{sha}"')
        if name == 'ingress':
            template = substitute(template, 'tasky.invalid', fqdn)
        require('registry.invalid/' not in template and 'tasky.invalid' not in template, 'Unresolved release placeholder')
        manifests.append(template.strip())
    path = work / 'deploy.yaml'
    write(path, '\n---\n'.join(manifests) + '\n')
    # Only the non-secret web manifest is mounted into the scanner containers.
    path.chmod(0o644)
    for tool in ([CHECKOV, '-f', '/scan/deploy.yaml', '--framework', 'kubernetes'],
                 [os.environ['TRIVY'], 'config', '--exit-code', '1', '--severity', 'UNKNOWN,HIGH,CRITICAL', '/scan/deploy.yaml']):
        result = subprocess.run(['docker', 'run', '--rm', '-v', f'{path}:/scan/deploy.yaml:ro', *tool], check=False)
        require(result.returncode == 0, 'Rendered deployment scan failed')


def verify(work):
    sha, images = release()
    name = os.environ.pop('CANDIDATE_NAME', '')
    require(name and '\n' not in name and '\r' not in name, 'Invalid marker input')
    expected = work / 'expected'
    try:
        write(expected, hashlib.sha256((name + '\n').encode()).hexdigest() + '\n')
        write(work / 'images.txt', f"{images['tasky']} {images['busybox']} {sha}\n")
        copy(SCRIPTS / 'verify.sh', work / 'verify.sh')
        request, logs = invoke(work, 'bash verify.sh', ['verify.sh', 'images.txt', 'expected'])
    finally:
        expected.unlink(missing_ok=True)
    evidence = re.fullmatch(r'node ([a-z0-9][a-z0-9.-]{0,252}) (' + UUID + r')\npod (web-[a-z0-9]+-[a-z0-9]+)\npod (web-[a-z0-9]+-[a-z0-9]+)\nmatch', logs)
    require(evidence and evidence[3] != evidence[4], 'Incomplete placement or marker evidence')
    record(f'AKS request `{request}` · revision `{sha}`')
    for repo, image in images.items():
        record(f'{repo} `{image.split("@")[1]}`')
    record(f'Node `{evidence[1]}` (`{evidence[2]}`) · pods `{evidence[3]}`, `{evidence[4]}`')
    record('match')


def main():
    os.umask(0o077)
    work = Path(os.environ['RUNNER_TEMP']) / 'outpost-cluster'
    work.mkdir(exist_ok=True, mode=0o700)
    actions = {'gate': lambda w: gate(w, 'infra'), 'release-gate': lambda w: gate(w, 'release'),
               'setup': setup, 'secret': secret, 'reader': reader, 'render': render, 'verify': verify}
    actions[sys.argv[1]](work)


if __name__ == '__main__':
    try:
        main()
    except (Failure, ValueError, KeyError, OSError, IndexError) as error:
        sys.exit(str(error) if isinstance(error, Failure) else 'Invalid workflow state or resource response')
