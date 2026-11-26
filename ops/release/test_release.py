"""Local tests use synthetic secrets and never contact Azure, a registry or a cluster."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import cluster

SHA = '1' * 40
SUB = 'aaaaaaaa-0000-0000-0000-aaaaaaaaaaaa'
REG = 'acroutpost123456789a.azurecr.io'
APP = 'sha256:' + 'a' * 64
INIT = 'sha256:' + 'b' * 64
# Verbatim kubectl 1.35.8 output captured 26 Nov through AKS Run Command (identity redacted).
REAL_CONFIGMAP_DENIAL = ('error: failed to create configmap: configmaps is forbidden: User "<redacted>" cannot create resource '
                         '"configmaps" in API group "" in the namespace "wiz-evidence": User does not have access to the '
                         'resource in Azure. Update role assignment to allow access.')
REAL_CRD_VALIDATION = ('error: error validating "STDIN": error validating data: failed to check CRD: failed to list CRDs: '
                       'customresourcedefinitions.apiextensions.k8s.io is forbidden: User "<redacted>" cannot list resource '
                       '"customresourcedefinitions" in API group "apiextensions.k8s.io" at the cluster scope')
ENV = dict(ACR_LOGIN_SERVER=REG, INGRESS_FQDN='outpost-123456789a.testhash.eastus2.sysgen.cloudapp.azure.com',
           REVISION=SHA, GITHUB_SHA=SHA, TASKY_DIGEST=APP, BUSYBOX_DIGEST=INIT,
           TASKY_CONFIG_DIGEST='sha256:'+'c'*64, BUSYBOX_CONFIG_DIGEST='sha256:'+'d'*64, ARM_SUBSCRIPTION_ID=SUB)


class Release(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        env = patch.dict(os.environ, ENV)
        env.start()
        self.addCleanup(env.stop)

    def test_arm_requires_complete_typed_result(self):
        ok = dict(provisioningState='Succeeded', id=SUB, exitCode=0, logs='proof')
        self.assertEqual(cluster.result(json.dumps(ok)), (SUB, 'proof'))
        for key, bad in [('exitCode', None), ('exitCode', False), ('exitCode', '0'), ('exitCode', 1), ('id', ''),
                         ('provisioningState', 'Running'), ('logs', None), ('id', '\nmalformed')]:
            with self.subTest(key=key, bad=bad), self.assertRaises(cluster.Failure):
                cluster.result(json.dumps(dict(ok, **{key: bad})))
        with self.assertRaisesRegex(cluster.Failure, 'Unexpected Kubernetes principal'):
            cluster.result(json.dumps(dict(ok, exitCode=42)), principal_gate=True)
        with self.assertRaisesRegex(cluster.Failure, 'cannot list nodes'):
            cluster.result(json.dumps(dict(ok, exitCode=15)), principal_gate=True)
        with patch.object(cluster, 'invoke', return_value=(SUB, 'unexpected response')), self.assertRaises(cluster.Failure):
            cluster.fixed(self.path, '', [], 'proof')

    def test_secret_dedicated_attachment_and_failure_cleanup(self):
        uri = 'mongodb://tasky:' + 'ab' * 24 + '@mongo.wiz.internal:27017/?authSource=admin'
        private = {'MONGODB_URI': uri, 'SECRET_KEY': 'sample-only' * 4}

        def inspect(work, command, files, proof):
            self.assertEqual(files, ['secret.json'])
            self.assertIn('--server-side', command)
            secret = work / files[0]
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
            data = json.loads(secret.read_text())['data']
            for k, v in private.items():
                self.assertNotIn(v, command)
                self.assertEqual(base64.b64decode(data[k]).decode(), v)
                self.assertNotIn(k, os.environ)
            raise cluster.Failure('synthetic failure')

        with patch.dict(os.environ, private), patch.object(cluster, 'fixed', side_effect=inspect), self.assertRaises(cluster.Failure):
            cluster.secret(self.path)
        self.assertFalse((self.path / 'secret.json').exists())
        for var, value in [('MONGODB_URI', 'mongodb://other'), ('SECRET_KEY', 'short')]:
            with patch.dict(os.environ, dict(private, **{var: value})), self.assertRaises(cluster.Failure):
                cluster.secret(self.path)
            self.assertFalse((self.path / 'secret.json').exists())

    def test_render_release_binds_both_digests_and_revision(self):
        with patch.object(cluster, 'scan') as scanners:
            cluster.render(self.path)
        rendered = (self.path / 'deploy.yaml').read_text()
        self.assertIn(f'{REG}/tasky@{APP}', rendered)
        self.assertIn(f'{REG}/busybox@{INIT}', rendered)
        self.assertIn(SHA, rendered)
        self.assertIn(ENV['INGRESS_FQDN'], rendered)
        self.assertNotIn('acroutpost0000000000.azurecr.io/', rendered)
        scanners.assert_called_once()
        self.assertTrue((self.path / 'scanned.sha256').is_file())
        with patch.object(cluster, 'fixed') as remote:
            cluster.deploy(self.path)
            self.assertIn('deploy.yaml', remote.call_args.args[2])
        (self.path / 'deploy.yaml').write_text(rendered + '# drift')
        with self.assertRaises(cluster.Failure):
            cluster.deploy(self.path)
        for var, bad in [('ACR_LOGIN_SERVER', REG + '.invalid'), ('INGRESS_FQDN', 'other.invalid'),
                         ('INGRESS_FQDN', 'outpost-0000000000.eastus2.cloudapp.azure.com'), ('TASKY_DIGEST', 'latest'),
                         ('BUSYBOX_DIGEST', '\nmalformed'), ('REVISION', '2' * 40)]:
            with patch.dict(os.environ, {var: bad}), self.assertRaises(cluster.Failure):
                cluster.render(self.path)
        with patch.object(cluster, 'scan', side_effect=cluster.Failure('scan failed')), self.assertRaises(cluster.Failure):
            cluster.render(self.path)

    def test_marker_proof_stays_private(self):
        sample = 'synthetic marker'
        expected = hashlib.sha256((sample + '\n').encode()).hexdigest()
        output = io.StringIO()

        def reply(work, command, files):
            self.assertEqual(files, ['verify.sh', 'images.txt', 'expected'])
            self.assertEqual((work / 'expected').read_text().strip(), expected)
            self.assertNotIn('CANDIDATE_NAME', os.environ)
            self.assertNotIn(expected, command)
            return SUB, f'node test-node {SUB}\npod web-bc123-a\npod web-bc123-b\nmatch'

        with patch.dict(os.environ, CANDIDATE_NAME=sample), patch.object(cluster, 'invoke', side_effect=reply), contextlib.redirect_stdout(output):
            cluster.verify(self.path)
        self.assertNotIn(sample, output.getvalue())
        self.assertNotIn(expected, output.getvalue())
        self.assertFalse((self.path / 'expected').exists())
        with patch.dict(os.environ, CANDIDATE_NAME=sample), patch.object(cluster, 'invoke', return_value=(SUB, 'untrusted raw logs')), self.assertRaises(cluster.Failure):
            cluster.verify(self.path)
        self.assertFalse((self.path / 'expected').exists())

    def test_authorization_wrong_identity_and_namespace_denial(self):
        kubectl = self.path / 'kubectl'
        kubectl.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
if args == ['auth', 'whoami', '-o', 'jsonpath={.status.userInfo.username}']:
    print(os.environ['MOCK_PRINCIPAL'])
elif args in (['auth', 'can-i', 'patch', 'deployments.apps', '-n', 'wiz-web'], ['auth', 'can-i', 'list', 'nodes']):
    print('yes')
elif args == ['create', '--validate=false', '-f', '-', '-o', 'jsonpath={.status.allowed}{"|"}{.status.evaluationError}{"|"}']:
    Path('review.json').write_text(sys.stdin.read())
    status = json.loads(os.environ['MOCK_REVIEW'])
    print(str(status.get('allowed', '')).lower(), status.get('evaluationError', ''), '', sep='|')
    sys.exit(int(os.environ['MOCK_STATUS']))
elif args == ['-n', 'wiz-evidence', 'create', 'configmap', 'outpost-release-boundary-check',
              '--from-literal=marker=synthetic', '--dry-run=server', '-o', 'name']:
    print(os.environ['MOCK_DRY_REASON'], file=sys.stderr)
    sys.exit(int(os.environ['MOCK_DRY_STATUS']))
else:
    sys.exit(1)
''')
        kubectl.chmod(0o700)
        (self.path / 'auth.txt').write_text(f'{SUB} {SUB} release\n')
        reason = REAL_CONFIGMAP_DENIAL
        legacy = ('Error from server (Forbidden): configmaps "outpost-release-boundary-check" is forbidden: User "x" '
                  'cannot create resource "configmaps" in API group "" in the namespace "wiz-evidence"')
        denial = {'allowed': False, 'reason': 'Azure does not have access'}
        cases = [(SUB, denial, 0, reason, 1, 0), ('unexpected', denial, 0, reason, 1, 42),
                 (SUB, {'allowed': True}, 0, reason, 1, 17), (SUB, dict(denial, evaluationError='webhook unavailable'), 0, reason, 1, 17),
                 (SUB, {}, 0, reason, 1, 17), (SUB, denial, 2, reason, 1, 16),
                 (SUB, denial, 0, '', 0, 18), (SUB, denial, 0, 'connection refused', 1, 19),
                 (SUB, denial, 0, legacy, 1, 0), (SUB, denial, 0, REAL_CRD_VALIDATION, 1, 19)]
        for principal, review, status, dry_reason, dry_status, expected in cases:
            with self.subTest(principal=principal, review=review, status=status, dry_reason=dry_reason):
                env = dict(os.environ, PATH=f"{self.path}:{os.environ['PATH']}", MOCK_PRINCIPAL=principal,
                           MOCK_REVIEW=json.dumps(review), MOCK_STATUS=str(status), MOCK_DRY_REASON=dry_reason, MOCK_DRY_STATUS=str(dry_status))
                reply = subprocess.run(['bash', cluster.SCRIPTS / 'auth.sh'], cwd=self.path, env=env, capture_output=True)
                self.assertEqual(reply.returncode, expected)
                self.assertEqual(reply.stdout + reply.stderr, b'')
        self.assertEqual(json.loads((self.path / 'review.json').read_text()), {
            'apiVersion': 'authorization.k8s.io/v1', 'kind': 'SelfSubjectAccessReview',
            'spec': {'resourceAttributes': {'namespace': 'wiz-evidence', 'verb': 'create', 'group': '', 'resource': 'configmaps'}}})

    def test_public_route_retries_tls_then_checks_direct_anonymous_gets(self):
        host = ENV['INGRESS_FQDN']
        for port in ('', ':443'):
            replies = [(60, b'000 0'), (0, b'200 0'), (0, f'308 https://{host}{port}/readyz'.encode())]
            with self.subTest(port=port), patch.object(cluster, 'time') as clock, patch.object(cluster, 'record') as record, \
                    patch.object(cluster, 'curl_status', side_effect=replies) as curl:
                cluster.public_route(self.path)
                clock.sleep.assert_called_once_with(10)
                self.assertEqual([call.args[0][-1] for call in curl.call_args_list],
                                 [f'https://{host}/readyz', f'https://{host}/readyz', f'http://{host}/readyz'])
                for call in curl.call_args_list:
                    args = call.args[0]
                    self.assertEqual(args[:4], ['curl', '-q', '--noproxy', '*'])
                    self.assertEqual(args[4:-2], ['--silent', '--max-time', '8', '--max-filesize', '65536',
                                                  '--output', os.devnull, '--write-out'])
                self.assertEqual([call.args[0] for call in record.call_args_list],
                                 ['Attempt 1: HTTPS readiness curl exit 60 (certificate not trusted yet), HTTP 000',
                                  'Public HTTPS readiness and HTTP redirect verified'])

    def test_public_route_fails_closed_without_printing_remote_data(self):
        host = ENV['INGRESS_FQDN']
        cases = [(b'503 0', b''), (b'200 7', b''), (b'200 0', f'200 https://{host}/readyz'.encode()),
                 (b'200 0', b'308 https://other.invalid/readyz'), (b'200 0', f'301 https://{host}/login'.encode()),
                 (b'200 0', f'302 http://{host}/readyz'.encode())]
        for ready, redirect in cases:
            def reply(args):
                return 0, (ready if args[-1].startswith('https://') else redirect)

            with self.subTest(ready=ready, redirect=redirect), patch.object(cluster, 'time') as clock, \
                    patch.object(cluster, 'curl_status', side_effect=reply), patch.object(cluster, 'record') as record:
                with self.assertRaisesRegex(cluster.Failure, '^Public HTTPS readiness or HTTP redirect verification failed$'):
                    cluster.public_route(self.path)
                self.assertEqual(clock.sleep.call_count, len(cluster.ROUTE_DELAYS) - 1)
                for call in record.call_args_list:
                    line = call.args[0]
                    self.assertRegex(line, r'^Attempt [0-9]+: ')
                    self.assertNotIn('other.invalid', line)
                    self.assertNotIn('/login', line)
                    self.assertNotIn(host, line)
        with patch.dict(os.environ, INGRESS_FQDN='wrong.invalid'), patch.object(cluster, 'curl_status') as curl:
            with self.assertRaises(cluster.Failure):
                cluster.public_route(self.path)
            curl.assert_not_called()

    def test_release_gate_retries_only_role_propagation(self):
        def outcome(codes):
            calls = iter(codes)
            def fake(*args, **kwargs):
                code = next(calls)
                if code:
                    raise cluster.CheckFailure(code)
            return fake
        with patch.dict(os.environ, ARM_CLIENT_ID=SUB, RELEASE_PRINCIPAL_ID=SUB), patch.object(cluster, 'arm', return_value='Succeeded Running'), \
                patch.object(cluster, 'time') as clock, patch.object(cluster, 'record'):
            clock.monotonic.return_value = 0
            with patch.object(cluster, 'fixed', side_effect=outcome([15, 14, 0])) as fixed:
                cluster.gate(self.path, 'release')
                self.assertEqual(fixed.call_count, 3)
            for code in (17, 19, 13):
                with self.subTest(code=code), patch.object(cluster, 'fixed', side_effect=outcome([code, 0])) as fixed:
                    with self.assertRaisesRegex(cluster.Failure, cluster.CHECKS[code]):
                        cluster.gate(self.path, 'release')
                    self.assertEqual(fixed.call_count, 1)

    def test_every_script_exit_code_has_a_label(self):
        import re
        seen = {}
        for script in sorted(cluster.SCRIPTS.glob('*.sh')):
            if script.name in ('login.sh', 'images.sh'):
                continue  # these run on the runner, not through AKS Run Command
            for code in map(int, re.findall(r'exit ([0-9]+)', script.read_text())):
                if code in (0, 42):
                    continue
                self.assertIn(code, cluster.CHECKS, f'{script.name} exit {code} has no label')
                self.assertTrue(cluster.CHECKS[code].startswith(script.stem.split('.')[0] + ':'), (script.name, code))
                seen.setdefault(code, script.name)
                self.assertEqual(seen[code], script.name, f'exit {code} reused across scripts')

    def test_remote_placement_and_marker_evidence(self):
        # kubectl fixture emits the projected fields for a current rollout and two pods.
        kubectl = self.path / 'kubectl'
        kubectl.write_text('''#!/usr/bin/env python3
import os, sys
a=sys.argv[1:]; bad=os.environ.get('BAD'); node='aks-web-1'; uid=os.environ['ARM_SUBSCRIPTION_ID']; rs='b'+uid[1:]
web=os.environ['ACR_LOGIN_SERVER']+'/tasky@'+os.environ['TASKY_DIGEST']; init=os.environ['ACR_LOGIN_SERVER']+'/busybox@'+os.environ['BUSYBOX_DIGEST']
if 'nodes' in a: print(node if bad!='duplicate node' else node+'\\nsecond')
elif 'node' in a: print('|'.join(['True',uid,'workload=web:NoSchedule,' if bad!='taint' else '']))
elif 'deploy' in a: print('|'.join(map(str,[uid,3,2 if bad=='stale generation' else 3,2,2,2,'' if bad=='rolling' else 2,2,4,web,init,os.environ['GITHUB_SHA']])))
elif 'rs' in a: print(rs,uid,3 if bad=='stale rs' else 4)
elif 'pods' in a:
    for name in ('web-abc-123','web-abc-456'):
        print('|'.join([name,'',rs,'True',node if bad!='wrong placement' else 'other','web',web,init if bad!='wrong init' else '-', 'workload:Equal:web:NoSchedule,',
                        'true','2026-11-26T00:00:00Z',web if bad!='runtime' else 'wrong','0',init]))
elif 'pod' in a: print('true|token' if bad=='token' else 'false|')
elif 'exec' in a and '/app/check-panel-marker-access' in a:
    # Real checker: exit 2 and no output without a token; a decision only with one.
    if bad=='checker': print('denied')
    else: sys.exit(2)
elif 'exec' in a: print('different' if bad=='marker' else 'synthetic')
else: sys.exit(1)
''')
        kubectl.chmod(0o700)
        (self.path / 'images.txt').write_text(f'{REG}/tasky@{APP} {REG}/busybox@{INIT} {SHA} {ENV["TASKY_CONFIG_DIGEST"]} {ENV["BUSYBOX_CONFIG_DIGEST"]}\n')
        (self.path / 'expected').write_text(hashlib.sha256(b'synthetic\n').hexdigest() + '\n')
        codes = {'': 0, 'duplicate node': 62, 'taint': 63, 'stale generation': 64, 'rolling': 65, 'stale rs': 66,
                 'wrong placement': 68, 'wrong init': 68, 'runtime': 71, 'marker': 73, 'token': 75, 'checker': 76}
        for bad, code in codes.items():
            with self.subTest(bad=bad):
                reply = subprocess.run(['bash', cluster.SCRIPTS / 'verify.sh'], cwd=self.path, capture_output=True,
                                       env=dict(os.environ, PATH=f"{self.path}:{os.environ['PATH']}", BAD=bad), check=False)
                self.assertEqual(reply.returncode, code, reply.stderr)
                if bad:
                    self.assertEqual(reply.stdout, b'')
                else:
                    self.assertTrue(reply.stdout.endswith(b'match\n'))
                self.assertNotIn(b'synthetic', reply.stdout + reply.stderr)

    def test_deploy_waits_for_the_outpost_revocation(self):
        kubectl = self.path / 'kubectl'
        kubectl.write_text('''#!/usr/bin/env python3
import os, sys
a=sys.argv[1:]; mode=os.environ['MODE']
with open('calls', 'a') as f: print(' '.join(a), file=f)
if 'pods' in a:
    if mode == 'unreadable': sys.exit(1)
    if mode != 'none': print('web-abc-123||True')
elif 'exec' in a:
    if mode == 'token-free': sys.exit(2)
    print('allowed' if mode == 'baseline' else 'denied')
elif 'apply' in a or 'rollout' in a: pass
else: sys.exit(1)
''')
        kubectl.chmod(0o700)
        (self.path / 'deploy.yaml').write_text('kind: List\n')
        for mode, code in (('baseline', 45), ('revoked', 0), ('token-free', 0), ('none', 0), ('unreadable', 46)):
            with self.subTest(mode=mode):
                (self.path / 'calls').unlink(missing_ok=True)
                reply = subprocess.run(['bash', cluster.SCRIPTS / 'deploy.sh'], cwd=self.path, capture_output=True,
                                       env=dict(os.environ, PATH=f"{self.path}:{os.environ['PATH']}", MODE=mode))
                self.assertEqual(reply.returncode, code)
                applied = ' apply ' in (self.path / 'calls').read_text()
                self.assertEqual(applied, code == 0, 'nothing may be applied while cluster-admin is live')

    def test_reader_proves_private_list_and_get(self):
        kubectl = self.path / 'kubectl'
        kubectl.write_text('#!/bin/sh\n[ "$*" = "-n wiz-evidence exec deployment/backup-reader -c reader -- /app/backup-reader" ] || exit 9\n'
                           'echo "20261126T084846Z-run/dump.archive.gz 1 private-listing"\nexit "$READER"\n')
        kubectl.chmod(0o700)
        for status, code, out in (('0', 0, b'backup verified privately\n'), ('1', 86, b'')):
            with self.subTest(status=status):
                reply = subprocess.run(['bash', cluster.SCRIPTS / 'reader.sh', 'verify'], cwd=self.path, capture_output=True,
                                       env=dict(os.environ, PATH=f"{self.path}:{os.environ['PATH']}", READER=status))
                self.assertEqual((reply.returncode, reply.stdout), (code, out))
        with patch.object(cluster, 'ingress', return_value=('host', '123456789a')), \
                patch.object(cluster, 'arm', side_effect=['acroutpost123456789a.azurecr.io', 'stoutpost123456789a']), \
                patch.object(cluster, 'invoke', return_value=(SUB, f'{REG}/tasky@{APP}')), \
                patch.object(cluster, 'scan'), patch.object(cluster, 'fixed') as fixed:
            cluster.reader(self.path)
        self.assertEqual([call.args[3] for call in fixed.call_args_list], ['reader ready', 'backup verified privately'])


if __name__ == '__main__':
    unittest.main()
