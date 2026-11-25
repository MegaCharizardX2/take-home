"""Exercise the real publisher script with local command doubles."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent


class Images(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.path = Path(work.name)
        (self.path / 'tasky').mkdir()
        (self.path / 'tools').mkdir()
        self.env = dict(os.environ, RUNNER_TEMP=work.name, PATH=f"{self.path / 'tools'}:{os.environ['PATH']}",
                        GITHUB_OUTPUT=str(self.path / 'outputs'), GITHUB_SHA='1' * 40, TRIVY='test-scanner',
                        ARM_TENANT_ID='aaaaaaaa-0000-0000-0000-aaaaaaaaaaaa', ACR_LOGIN_SERVER='acroutpost123456789a.azurecr.io')
        docker = self.path / 'tools/docker'
        docker.write_text('''#!/usr/bin/env bash
set -eu
if [[ $1 == build ]]; then
    [[ -z ${CANDIDATE_NAME:-} ]] || exit 9
    [[ -f tasky/wizexercise.txt ]] || exit 9
    cp tasky/wizexercise.txt "$RUNNER_TEMP/built"
elif [[ $1 == run && $* == *--entrypoint* ]]; then
    cat "$RUNNER_TEMP/built"
elif [[ $1 == pull || $1 == tag ]]; then
    exit 0
elif [[ $1 == image && $* == *Architecture* ]]; then
    echo linux/amd64
elif [[ $1 == image ]]; then
    printf 'sha256:%064d\\n' 1
elif [[ $1 == save ]]; then
    touch "$3"
elif [[ $1 == run && $* == *test-scanner* ]]; then
    [[ -f "$RUNNER_TEMP/outpost-images/image.tar" && $* == *UNKNOWN,HIGH,CRITICAL* ]] || exit 9
    [[ ${MOCK_ERROR:-} != scan ]] || exit 1
elif [[ $1 == login ]]; then
    read -r token; [[ $token == synthetic-refresh ]] || exit 9
elif [[ $1 == push ]]; then
    [[ $2 == --platform && $3 == linux/amd64 ]] || exit 9
    printf '%s: digest: sha256:%064d size: 10\\n' "$GITHUB_SHA" 2
elif [[ $1 == buildx ]]; then
    value=1; [[ ${MOCK_ERROR:-} != config ]] || value=3
    printf '{"schemaVersion":2,"config":{"digest":"sha256:%064d"},"layers":[]}' "$value"
else
    exit 9
fi
''')
        for tool, command in [('az', 'echo synthetic-entra'), ('curl', "cat >/dev/null; echo '{\"refresh_token\":\"synthetic-refresh\"}'")]:
            (self.path / 'tools' / tool).write_text('#!/bin/sh\n' + command + '\n')
        for tool in (self.path / 'tools').iterdir():
            tool.chmod(0o700)

    def phase(self, name, **env):
        return subprocess.run(['bash', SCRIPTS / 'images.sh', name], env=dict(self.env, **env),
                              cwd=self.path, capture_output=True, check=False)

    def test_marker_scan_and_push(self):
        result = self.phase('build', CANDIDATE_NAME='synthetic name')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'match\n')
        self.assertFalse((self.path / 'tasky/wizexercise.txt').exists())
        self.assertEqual(self.phase('scan').returncode, 0)
        self.assertFalse((self.path / 'outpost-images/image.tar').exists())
        result = self.phase('push')
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = (self.path / 'outputs').read_text().splitlines()
        expected = []
        for repo in ('tasky', 'busybox'):
            expected.extend([f'{repo}=sha256:{2:064d}', f'{repo}_config=sha256:{1:064d}'])
        self.assertEqual(outputs, expected + ['revision=' + '1' * 40])

    def test_malformed_private_inputs_scans_and_config_mismatch_fail_closed(self):
        self.assertNotEqual(self.phase('build', CANDIDATE_NAME='').returncode, 0)
        self.assertFalse((self.path / 'tasky/wizexercise.txt').exists())
        self.assertNotEqual(self.phase('scan', MOCK_ERROR='scan').returncode, 0)
        self.assertFalse((self.path / 'outpost-images/image.tar').exists())
        self.assertEqual(self.phase('scan').returncode, 0)
        self.assertNotEqual(self.phase('push', MOCK_ERROR='config').returncode, 0)
        self.assertNotEqual(self.phase('push', ACR_LOGIN_SERVER='outside.example').returncode, 0)
        self.assertFalse((self.path / 'outputs').exists())
