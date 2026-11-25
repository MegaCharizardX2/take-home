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
ENV = dict(ACR_LOGIN_SERVER=REG, INGRESS_FQDN='outpost-123456789a.testhash.eastus2.cloudapp.azure.com',
           REVISION=SHA, GITHUB_SHA=SHA, TASKY_DIGEST=APP, BUSYBOX_DIGEST=INIT, TRIVY='scanner', ARM_SUBSCRIPTION_ID=SUB)


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
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as scanners:
            cluster.render(self.path)
        rendered = (self.path / 'deploy.yaml').read_text()
        self.assertIn(f'{REG}/tasky@{APP}', rendered)
        self.assertIn(f'{REG}/busybox@{INIT}', rendered)
        self.assertIn(SHA, rendered)
        self.assertIn(ENV['INGRESS_FQDN'], rendered)
        self.assertNotIn('registry.invalid', rendered)
        self.assertEqual(scanners.call_count, 2)
        for var, bad in [('ACR_LOGIN_SERVER', REG + '.invalid'), ('INGRESS_FQDN', 'other.invalid'),
                         ('INGRESS_FQDN', 'outpost-0000000000.eastus2.cloudapp.azure.com'), ('TASKY_DIGEST', 'latest'),
                         ('BUSYBOX_DIGEST', '\nmalformed'), ('REVISION', '2' * 40)]:
            with patch.dict(os.environ, {var: bad}), self.assertRaises(cluster.Failure):
                cluster.render(self.path)
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)), self.assertRaises(cluster.Failure):
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
        kubectl.write_text("""#!/bin/sh
case "$*" in
  *whoami*) echo "$MOCK_PRINCIPAL" ;;
  *wiz-evidence*) echo "$MOCK_DENIAL"; exit "$MOCK_STATUS" ;;
  *can-i*) echo yes ;;
  *) exit 1 ;;
esac
""")
        kubectl.chmod(0o700)
        (self.path / 'auth.txt').write_text(f'{SUB} {SUB} release\n')
        for principal, response, status, expected in [(SUB, 'no', 1, 0), ('unexpected', 'no', 1, 42),
                                                       (SUB, 'yes', 0, 1), (SUB, 'Forbidden', 1, 1)]:
            with self.subTest(principal=principal, response=response):
                env = dict(os.environ, PATH=f"{self.path}:{os.environ['PATH']}", MOCK_PRINCIPAL=principal,
                           MOCK_DENIAL=response, MOCK_STATUS=str(status))
                reply = subprocess.run(['bash', cluster.SCRIPTS / 'auth.sh'], cwd=self.path, env=env, capture_output=True)
                self.assertEqual(reply.returncode, expected)

    def test_remote_placement_and_marker_evidence(self):
        # kubectl fixture emits the projected fields for a current rollout and two pods.
        kubectl = self.path / 'kubectl'
        kubectl.write_text('''#!/usr/bin/env python3
import os, sys
a=sys.argv[1:]; bad=os.environ.get('BAD'); node='aks-web-1'; uid=os.environ['ARM_SUBSCRIPTION_ID']; rs='b'+uid[1:]
web=os.environ['ACR_LOGIN_SERVER']+'/tasky@'+os.environ['TASKY_DIGEST']; init=os.environ['ACR_LOGIN_SERVER']+'/busybox@'+os.environ['BUSYBOX_DIGEST']
if 'nodes' in a: print(node if bad!='duplicate node' else node+'\\nsecond')
elif 'node' in a: print('True',uid,'workload=web:NoSchedule,' if bad!='taint' else '-')
elif 'deploy' in a: print(uid,3,2 if bad=='stale generation' else 3,2,2,2,2,2,4,web,init,os.environ['GITHUB_SHA'])
elif 'rs' in a: print(rs,uid,3 if bad=='stale rs' else 4)
elif 'pods' in a:
    for name in ('web-abc-123','web-abc-456'):
        print('|'.join([name,'',rs,'True',node if bad!='wrong placement' else 'other','web',web,init if bad!='wrong init' else '-', 'workload:Equal:web:NoSchedule,']))
elif 'exec' in a: print('different' if bad=='marker' else 'synthetic')
else: sys.exit(1)
''')
        kubectl.chmod(0o700)
        (self.path / 'images.txt').write_text(f'{REG}/tasky@{APP} {REG}/busybox@{INIT} {SHA}\n')
        (self.path / 'expected').write_text(hashlib.sha256(b'synthetic\n').hexdigest() + '\n')
        for bad in ('', 'duplicate node', 'taint', 'stale generation', 'stale rs', 'wrong placement', 'wrong init', 'marker'):
            with self.subTest(bad=bad):
                reply = subprocess.run(['bash', cluster.SCRIPTS / 'verify.sh'], cwd=self.path, capture_output=True,
                                       env=dict(os.environ, PATH=f"{self.path}:{os.environ['PATH']}", BAD=bad), check=False)
                self.assertEqual(reply.returncode == 0, bad == '', reply.stderr)
                if bad:
                    self.assertEqual(reply.stdout, b'')
                else:
                    self.assertTrue(reply.stdout.endswith(b'match\n'))
                self.assertNotIn(b'synthetic', reply.stdout + reply.stderr)


if __name__ == '__main__':
    unittest.main()
