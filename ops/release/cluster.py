"""Protected workflow steps. Only allowlisted evidence leaves the runner's private directory."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from arm_transport import completed_reply, PollError

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'ops/release'
UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
DIGEST = r'sha256:[a-f0-9]{64}'
REGISTRY = r'acroutpost[0-9a-f]{10}\.azurecr\.io'
FQDN = r'outpost-[0-9a-f]{10}(?:\.[a-z0-9-]{1,63})?\.eastus2(?:\.sysgen)?\.cloudapp\.azure\.com'  # scoped labels (NoReuse) add a hash and .sysgen
ACR_PLACEHOLDER = 'acroutpost0000000000.azurecr.io/{}@sha256:' + '0' * 64
TRAEFIK_SHA = '29cbf019c5e013d9455c89fa29be66d2dd9007c84ed51b969220225fd1b7983c'
TRAEFIK_URL = 'https://traefik.github.io/charts/traefik/traefik-43.0.0.tgz'
CHECKOV = 'bridgecrew/checkov@sha256:89a4c477508225cdc3ed8a23d15c7e0d9d3029bc8ae192b7f113a6ff5f210c94'
TRIVY = 'aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb'


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
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as out:
        os.fchmod(out.fileno(), 0o600)
        out.write(value)


def copy(path, target):
    write(target, path.read_text())


def record(line):
    print(line, flush=True)
    if 'GITHUB_STEP_SUMMARY' in os.environ:
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as summary:
            print(line, file=summary)
            print(file=summary)


# Fixed, secret-free labels for the numbered exits of every Run Command script.
CHECKS = {
    # auth.sh
    11: 'auth: cannot create namespaces', 12: 'auth: cannot create cluster role bindings', 13: 'auth: invalid gate mode',
    14: 'auth: cannot patch deployments in wiz-web', 15: 'auth: cannot list nodes', 16: 'auth: access review request failed',
    17: 'auth: access review did not cleanly deny wiz-evidence configmaps', 18: 'auth: wiz-evidence configmap write was allowed',
    19: 'auth: wiz-evidence write failed for a reason other than RBAC',
    # platform.sh
    21: 'platform: namespaces apply failed', 22: 'platform: platform resources apply failed',
    23: 'platform: namespace, web service account or marker missing', 24: 'platform: web phase record unreadable',
    25: 'platform: cluster-admin binding present without a baseline phase record', 26: 'platform: web phase record create failed',
    28: 'platform: web phase advance failed',
    29: 'platform: cluster-admin binding present in the Outpost phase', 30: 'platform: unknown web phase',
    # traefik.sh
    31: 'traefik: helm install failed', 32: 'traefik: controller rollout not ready',
    33: 'traefik: ingress class missing', 34: 'traefik: load balancer IP is not pip-ingress',
    # deploy.sh (42 stays reserved for the principal gate)
    41: 'deploy: server dry-run rejected the manifest', 43: 'deploy: apply failed', 44: 'deploy: web rollout not ready in time',
    45: 'deploy: a running web pod still holds cluster-admin; run cluster setup outpost first',
    46: 'deploy: running web pods unreadable',
    # verify.sh
    61: 'verify: invalid release inputs', 62: 'verify: web node missing or not unique', 63: 'verify: web node not ready or missing its taint',
    64: 'verify: deployment state unreadable or generation not observed', 65: 'verify: replicas, images or revision differ from the release',
    66: 'verify: current ReplicaSet not found', 67: 'verify: a pod is not current or not ready',
    68: 'verify: pod placement, selector or images wrong', 69: 'verify: pod toleration missing',
    70: 'verify: web container not running or init container failed', 71: 'verify: web image ID differs from the pushed digest',
    72: 'verify: init image ID differs from the pushed digest', 73: 'verify: marker file content differs',
    74: 'verify: not exactly two verified pods', 75: 'verify: a web pod still has a service-account token',
    76: 'verify: marker check did not report a missing credential',
    # reader.sh
    81: 'reader: web rollout not ready', 82: 'reader: web image unreadable', 83: 'reader: reader apply failed',
    84: 'reader: reader rollout not ready', 85: 'reader: invalid reader mode',
    86: 'reader: private list, download or checksum of the newest backup failed',
    # outpost.sh
    101: 'outpost: web phase record unreadable', 102: 'outpost: web phase is neither baseline nor outpost',
    103: 'outpost: cluster-admin binding lookup failed', 104: 'outpost: no ready web pod to observe',
    105: 'outpost: marker check failed or contradicts the pod credential', 106: 'outpost: binding delete failed',
    107: 'outpost: binding still present after delete', 108: 'outpost: web identity still allowed after revocation',
    109: 'outpost: observed pod was replaced during the transition', 110: 'outpost: web phase advance failed',
    111: 'outpost: cluster-admin binding present in the Outpost phase',
}
# Azure role assignments can take minutes to reach the cluster: retry only these release checks.
RELEASE_RETRYABLE = {14, 15}


class CheckFailure(Failure):
    def __init__(self, code):
        super().__init__('Kubernetes check failed: ' + CHECKS[code])
        self.code = code


def result(reply, *, principal_gate=False):
    doc = json.loads(reply)
    require(isinstance(doc, dict) and doc.get('provisioningState') == 'Succeeded', 'ARM operation failed')
    code = doc.get('exitCode')
    if principal_gate and type(code) is int and code == 42:
        raise Failure('Unexpected Kubernetes principal')
    if type(code) is int and code in CHECKS:
        raise CheckFailure(code)
    require(type(code) is int, 'Missing remote exit code')
    require(code == 0, f'Remote command failed with exit code {code}')
    # Azure CLI returns commandResults.name as id or a full ARM resource ID.
    prefix = r'/subscriptions/' + UUID + r'/resourceGroups/takehome-rg/providers/Microsoft\.ContainerService/managedClusters/aks-outpost/commandResults/'
    request = checked(doc.get('id'), rf'(?i)(?:{prefix})?(?:[0-9a-f]{{32}}|{UUID})', 'AKS request ID')
    require(isinstance(doc.get('logs'), str), 'Missing AKS command logs')
    return request, doc['logs'].strip()


def invoke(work, command, files, *, timeout=390, principal_gate=False):
    deadline = time.monotonic() + timeout
    args = ['az', 'aks', 'command', 'invoke', '-g', 'takehome-rg', '-n', 'aks-outpost',
            '--subscription', env('ARM_SUBSCRIPTION_ID', UUID), '--only-show-errors', '-o', 'json']
    for name in files:
        require(Path(name).name == name and (work / name).is_file(), 'Missing AKS attachment')
        args += ['--file', name]
    first = run(args + ['--command', command], timeout=timeout, cwd=work)
    def fetch(command_id, remaining):
        return run(['az', 'aks', 'command', 'result', '-g', 'takehome-rg', '-n', 'aks-outpost',
                    '--subscription', env('ARM_SUBSCRIPTION_ID', UUID), '--command-id', command_id,
                    '--only-show-errors', '-o', 'json'], timeout=remaining)
    try:
        reply = completed_reply(first, fetch, deadline)
    except PollError as error:
        raise Failure(str(error)) from None
    return result(reply, principal_gate=principal_gate)


def fixed(work, command, files, proof, **kwargs):
    request, logs = invoke(work, command, files, **kwargs)
    require(logs == proof, 'Missing expected Kubernetes result')
    record(f'{proof} · AKS request `{request}`')


def gate(work, mode):
    deadline = time.monotonic() + (900 if mode == 'infra' else 360)
    client = env('ARM_CLIENT_ID', UUID)
    aks = arm('aks', 'show', '-g', 'takehome-rg', '-n', 'aks-outpost', '--query', '[provisioningState,powerState.code]')
    require(aks.split() == ['Succeeded', 'Running'], 'AKS unavailable')
    if mode == 'infra':
        group = ['-g', 'takehome-rg']
        vm = arm('vm', 'get-instance-view', *group, '-n', 'vm-mongo', '--query', "instanceView.statuses[?code=='PowerState/running'].code | [0]")
        require(vm == 'PowerState/running', 'Database VM unavailable')
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
            if str(error) == 'Unexpected Kubernetes principal':
                raise
            if mode == 'release' and getattr(error, 'code', None) not in RELEASE_RETRYABLE:
                raise
            last = str(error)
            record(f'{last}; retrying while Azure role assignments propagate')
        time.sleep(max(0, min(delay, deadline - time.monotonic())))
        delay = min(2 * delay, 60)
    raise Failure('Authorization deadline exceeded: ' + last)


def ingress():
    fqdn = checked(arm('network', 'public-ip', 'show', '-g', 'takehome-rg', '-n', 'pip-ingress', '--query', 'dnsSettings.fqdn'), FQDN, 'ingress FQDN')
    return fqdn, fqdn.split('.')[0].removeprefix('outpost-')


def substitute(text, placeholder, replacement):
    require(placeholder in text, 'Expected template placeholder missing')
    return text.replace(placeholder, replacement)


def scan(work, files, registries):
    """Scan only public manifests; Kubernetes Secret attachments never enter this directory."""
    with tempfile.TemporaryDirectory(dir=work) as directory:
        root = Path(directory)
        inputs, policy = root / 'manifests', root / 'policy'
        inputs.mkdir(); policy.mkdir()
        for name, source in files.items():
            dest = inputs / name
            dest.parent.mkdir(exist_ok=True, parents=True)
            copy(source, dest)
        data = policy / 'data'
        data.mkdir()
        write(data / 'trusted.json', json.dumps({'ksv0125': {'trusted_registries': registries}}))
        copy(ROOT / '.trivyignore.yaml', policy / 'exceptions.yaml')
        base = ['docker', 'run', '--rm', '--user', f'{os.getuid()}:{os.getgid()}', '-e', 'HOME=/tmp',
                '-v', f'{inputs}:/scan:ro', '-w', '/scan']
        from_checkov = json.loads(run(base + ['--network', 'none', CHECKOV, '-d', '/scan', '--framework', 'kubernetes',
                                             '--skip-download', '-o', 'json'], timeout=180))
        summary = from_checkov['summary']
        require(summary['passed'] > 0 and not summary['failed'] and not summary['parsing_errors'], 'Incomplete Checkov scan')
        run(base + ['-v', f'{policy}:/policy:ro', TRIVY, 'config', '--cache-dir', '/tmp/trivy',
                    '--config-data', '/policy/data', '--ignorefile', '/policy/exceptions.yaml', '--format', 'json',
                    '--exit-code', '1', '/scan'], timeout=180)


def setup(work):
    reader_id = checked(arm('identity', 'show', '-g', 'takehome-rg', '-n', 'id-backup-reader', '--query', 'clientId'), UUID, 'reader client ID')
    names = ('namespaces', 'identities', 'marker', 'network', 'bindings', 'traefik-secret-watch')
    for name in names:
        source = (ROOT / f'k8s/platform/{name}.yaml').read_text()
        if name == 'identities':
            source = substitute(source, '00000000-0000-0000-0000-000000000000', reader_id)
        write(work / f'{name}.yaml', source)
    scan(work, {f'platform/{name}.yaml': work / f'{name}.yaml' for name in names}, [])
    copy(SCRIPTS / 'platform.sh', work / 'platform.sh')
    fixed(work, 'bash platform.sh 2>/dev/null', ['platform.sh'] + [f'{name}.yaml' for name in names], 'platform ready')


def traefik(work):
    fqdn, _ = ingress()
    lock = json.loads((ROOT / 'k8s/traefik/chart.lock').read_text())
    require(lock.get('version') in ('43.0.0', 'v43.0.0') and lock.get('sha256') == TRAEFIK_SHA and lock.get('url') == TRAEFIK_URL, 'Unexpected Traefik chart lock')
    chart = run(['curl', '--proto', '=https', '--proto-redir', '=https', '--location', '--fail', '--silent', '--max-time', '60', TRAEFIK_URL])
    require(hashlib.sha256(chart).hexdigest() == TRAEFIK_SHA, 'Traefik chart verification failed')
    (work / 'traefik.tgz').write_bytes(chart)
    values = (ROOT / 'k8s/traefik/values.yaml').read_text()
    write(work / 'values.yaml', substitute(values, 'tasky.invalid', fqdn))
    manifest = run(['helm', 'template', 'traefik', './traefik.tgz', '--namespace', 'traefik', '--kube-version',
                    '1.36.5', '--skip-crds', '--values', 'values.yaml'], cwd=work).decode()
    trusted_image = 'docker.io/library/traefik@sha256:00c9734983e74ae35a1fc18eaee9e9da13f3dde95c4e45b3b8c3b60e0dbd2d17'
    require(re.findall(r'^\s*image:\s*(\S+)\s*$', manifest, re.MULTILINE) == [trusted_image], 'Unexpected controller image')
    run(['docker', 'run', '--rm', TRIVY, 'image', '--image-src', 'remote', '--platform', 'linux/amd64',
         '--severity', 'UNKNOWN,HIGH,CRITICAL', '--exit-code', '1', '--format', 'json', trusted_image], timeout=420)
    write(work / 'controller.yaml', manifest)
    scan(work, {'controller.yaml': work / 'controller.yaml', 'platform/network.yaml': ROOT / 'k8s/platform/network.yaml'}, ['docker.io'])
    address = ipaddress.IPv4Address(arm('network', 'public-ip', 'show', '-g', 'takehome-rg', '-n', 'pip-ingress', '--query', 'ipAddress'))
    require(address.is_global and not address.is_multicast, 'Unexpected ingress frontend IP')
    write(work / 'frontend-ip', str(address) + '\n')
    copy(SCRIPTS / 'traefik.sh', work / 'traefik.sh')
    fixed(work, 'bash traefik.sh 2>/dev/null', ['traefik.sh', 'values.yaml', 'traefik.tgz', 'frontend-ip'], 'traefik ready', timeout=570)


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
        command = ("trap 'rm -f -- secret.json' EXIT; kubectl -n wiz-web apply --server-side --field-manager=outpost-infra -f secret.json >/dev/null 2>&1 && "
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
    account = 'stoutpost' + suffix
    require(arm('storage', 'account', 'show', '-g', 'takehome-rg', '-n', account, '--query', 'name') == account, 'Backup account mismatch')
    write(work / 'reader.yaml', substitute(template, 'stoutpost0000000000', account))
    scan(work, {'reader/deployment.yaml': work / 'reader.yaml', 'platform/network.yaml': ROOT / 'k8s/platform/network.yaml'}, [registry])
    fixed(work, 'bash reader.sh apply 2>/dev/null', ['reader.sh', 'reader.yaml'], 'reader ready')
    fixed(work, 'bash reader.sh verify 2>/dev/null', ['reader.sh'], 'backup verified privately', timeout=240)


OUTPOST_EVIDENCE = re.compile(r'pod (web-[a-z0-9]+-[a-z0-9]+) (' + UUID + r')\nbefore (allowed|denied|absent)\n'
                              r'after (denied|absent)\nphase outpost')


def outpost(work):
    """Revoke the web identity's cluster-admin binding and prove it on one running pod."""
    copy(SCRIPTS / 'outpost.sh', work / 'outpost.sh')
    request, logs = invoke(work, 'bash outpost.sh 2>/dev/null', ['outpost.sh'], timeout=390)
    evidence = OUTPOST_EVIDENCE.fullmatch(logs)
    require(evidence, 'Incomplete web identity evidence')
    pod, uid, before, after = evidence.groups()
    # A token-bearing pod answers allowed/denied; a token-free pod is absent both times.
    require((before == 'absent') == (after == 'absent'), 'Inconsistent web identity evidence')
    record(f'Web identity transition · AKS request `{request}`')
    record(f'Pod `{pod}` (`{uid}`): before revocation `{before}`, after revocation `{after}` on the same pod')
    record('cluster-admin binding wiz-web-baseline absent · phase outpost')


def release():
    registry = env('ACR_LOGIN_SERVER', REGISTRY)
    sha = env('REVISION', r'[0-9a-f]{40}')
    require(sha == os.environ.get('GITHUB_SHA'), 'Published revision differs from workflow checkout')
    images = {repo: f'{registry}/{repo}@' + env(f'{repo.upper()}_DIGEST', DIGEST) for repo in ('tasky', 'busybox')}
    require(all(not image.endswith('0' * 64) for image in images.values()), 'Unresolved image digest')
    return sha, images


def render(work):
    sha, images = release()
    fqdn = env('INGRESS_FQDN', FQDN)
    require(fqdn.split('.')[0].removeprefix('outpost-') == env('ACR_LOGIN_SERVER', REGISTRY).split('.')[0].removeprefix('acroutpost'), 'Registry and ingress belong to different instances')
    files = {}
    for name in ('deployment', 'service', 'ingress'):
        template = (ROOT / f'k8s/web/{name}.yaml').read_text()
        if name == 'deployment':
            for repo, image in images.items():
                template = substitute(template, ACR_PLACEHOLDER.format(repo), image)
            template = substitute(template, 'outpost.wiz/revision: "' + '0' * 40 + '"', f'outpost.wiz/revision: "{sha}"')
        if name == 'ingress':
            template = substitute(template, 'tasky.invalid', fqdn)
        require('acroutpost0000000000.azurecr.io/' not in template and 'tasky.invalid' not in template, 'Unresolved release placeholder')
        dest = work / ('web-' + name + '.yaml')
        write(dest, template.strip() + '\n')
        files['web/' + name + '.yaml'] = dest
    scan(work, {**files, 'platform/network.yaml': ROOT / 'k8s/platform/network.yaml'}, [env('ACR_LOGIN_SERVER', REGISTRY)])
    path = work / 'deploy.yaml'
    write(path, '---\n'.join(file.read_text() for file in files.values()))
    write(work / 'scanned.sha256', hashlib.sha256(path.read_bytes()).hexdigest())
    if 'GITHUB_STEP_SUMMARY' in os.environ:
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as summary:
            print('<details><summary>Scanned release manifest</summary>\n\n~~~yaml', file=summary)
            print(path.read_text(), file=summary)
            print('~~~\n\n</details>', file=summary)


CURL_HINTS = {0: 'responded', 6: 'DNS lookup failed', 7: 'connection refused', 28: 'timed out',
              35: 'TLS handshake failed', 60: 'certificate not trusted yet'}
# The first Let's Encrypt HTTP-01 order starts when the app Ingress appears: allow about 7 minutes.
ROUTE_DELAYS = (0, 10, 20, 30, 30, 30, 60, 60, 60, 60, 60)


def curl_status(args):
    """Run curl without raising; return its exit code and stdout (the write-out text only)."""
    try:
        reply = subprocess.run(args, capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return -1, b''
    return reply.returncode, reply.stdout


def http_code(text):
    code = text.partition(b' ')[0]
    return code.decode() if re.fullmatch(rb'[0-9]{3}', code) else '-'


def public_route(_work):
    host = env('INGRESS_FQDN', FQDN)
    https = f'https://{host}/readyz'
    targets = (https.encode(), f'https://{host}:443/readyz'.encode())
    # Disable curl startup config and proxies so these requests are anonymous and direct.
    curl = ['curl', '-q', '--noproxy', '*', '--silent', '--max-time', '8', '--max-filesize', '65536',
            '--output', os.devnull, '--write-out']
    for attempt, delay in enumerate(ROUTE_DELAYS, 1):
        if delay:
            time.sleep(delay)
        code, ready = curl_status(curl + ['%{http_code} %{size_download}', https])
        if code != 0 or ready != b'200 0':
            # Only curl's exit code and the 3-digit HTTP status are logged, never response data.
            record(f'Attempt {attempt}: HTTPS readiness curl exit {code} '
                   f'({CURL_HINTS.get(code, "other")}), HTTP {http_code(ready)}')
            continue
        code, redirect = curl_status(curl + ['%{http_code} %{redirect_url}', f'http://{host}/readyz'])
        status, _, target = redirect.partition(b' ')
        if code == 0 and status in (b'301', b'302', b'303', b'307', b'308') and target in targets:
            record('Public HTTPS readiness and HTTP redirect verified')
            return
        record(f'Attempt {attempt}: HTTP redirect check failed, curl exit {code}, HTTP {http_code(redirect)}')
    raise Failure('Public HTTPS readiness or HTTP redirect verification failed')


def deploy(work):
    require(hashlib.sha256((work / 'deploy.yaml').read_bytes()).hexdigest() == (work / 'scanned.sha256').read_text(),
            'Deployment changed after scan')
    copy(SCRIPTS / 'deploy.sh', work / 'deploy.sh')
    fixed(work, 'bash deploy.sh 2>/dev/null', ['deploy.sh', 'deploy.yaml'], 'rollout ready', timeout=520)


def verify(work):
    sha, images = release()
    name = os.environ.pop('CANDIDATE_NAME', '')
    require(name and '\n' not in name and '\r' not in name, 'Invalid marker input')
    expected = work / 'expected'
    try:
        write(expected, hashlib.sha256((name + '\n').encode()).hexdigest() + '\n')
        app_config, init_config = env('TASKY_CONFIG_DIGEST', DIGEST), env('BUSYBOX_CONFIG_DIGEST', DIGEST)
        write(work / 'images.txt', f"{images['tasky']} {images['busybox']} {sha} {app_config} {init_config}\n")
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
               'setup': setup, 'secret': secret, 'traefik': traefik, 'reader': reader, 'outpost': outpost,
               'render': render, 'deploy': deploy,
               'verify': verify, 'public-route': public_route}
    actions[sys.argv[1]](work)


if __name__ == '__main__':
    try:
        main()
    except (Failure, ValueError, KeyError, OSError, IndexError) as error:
        sys.exit(str(error) if isinstance(error, Failure) else 'Invalid workflow state or resource response')
