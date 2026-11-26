"""Exercise platform setup and the Outpost web identity transition against local kubectl doubles."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import cluster

SCRIPT = Path(__file__).with_name("platform.sh")
OUTPOST = Path(__file__).with_name("outpost.sh")
POD_UID = "0a1b2c3d-0000-4000-8000-" + "1" * 12

PLATFORM_KUBECTL = """#!/usr/bin/env python3
import os, sys
from pathlib import Path
a=sys.argv[1:]; root=Path(os.environ['FIXTURE']); phase=root/'phase'; binding=root/'binding'
with (root/'calls').open('a') as f: print(' '.join(a), file=f)
if 'configmap' in a and 'outpost-web-phase' in a:
    if 'get' in a: print(phase.read_text() if phase.exists() else '')
    elif 'create' in a: phase.write_text(a[-1].split('=')[-1])
    elif 'patch' in a: phase.write_text('outpost')
    else: sys.exit(2)
elif 'clusterrolebinding' in a:
    print('clusterrolebinding/wiz-web-baseline' if binding.exists() else '')
elif 'create' in a and '-f' in a: sys.exit(9)
elif a[0]!='apply' and 'get' not in a: sys.exit(2)
"""


class PlatformTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        tool = self.root / "kubectl"
        tool.write_text(PLATFORM_KUBECTL)
        tool.chmod(0o700)
        self.env = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}", FIXTURE=str(self.root))

    def invoke(self):
        return subprocess.run(["bash", SCRIPT], cwd=self.root, env=self.env, capture_output=True).returncode

    def test_setup_never_grants_cluster_admin(self):
        # Fresh hardened build: no phase record yet, so it starts in the Outpost phase.
        self.assertEqual(self.invoke(), 0)
        self.assertEqual((self.root / "phase").read_text(), "outpost")
        self.assertEqual(self.invoke(), 0)
        self.assertFalse((self.root / "binding").exists())
        self.assertNotIn("baseline-binding", (self.root / "calls").read_text())

    def test_phases(self):
        cases = [("", True, 25), ("initializing", False, 0), ("initializing", True, 25),
                 ("baseline", True, 0), ("baseline", False, 0), ("outpost", False, 0), ("outpost", True, 29),
                 ("unknown", False, 30)]
        for phase, binding, code in cases:
            with self.subTest(phase=phase, binding=binding):
                (self.root / "phase").unlink(missing_ok=True)
                if phase:
                    (self.root / "phase").write_text(phase)
                (self.root / "binding").unlink(missing_ok=True)
                if binding:
                    (self.root / "binding").write_text("yes")
                self.assertEqual(self.invoke(), code)
                if phase == "initializing" and code == 0:
                    self.assertEqual((self.root / "phase").read_text(), "outpost")
                if phase == "baseline":
                    # The live binding is left for the outpost step's same-pod proof.
                    self.assertEqual((self.root / "binding").exists(), binding)
                    self.assertEqual((self.root / "phase").read_text(), "baseline")


# A fake cluster: web pod state, the binding, the phase record and the pod's own
# marker check (which answers from the binding, like the real authorizer).
OUTPOST_KUBECTL = r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
a = sys.argv[1:]; root = Path(os.environ['FIXTURE']); state = json.loads((root/'state.json').read_text())
def save(): (root/'state.json').write_text(json.dumps(state))
with (root/'calls').open('a') as f: print(json.dumps(a), file=f)
if 'outpost-web-phase' in a:
    if 'get' in a: print(state['phase'], end='')
    elif 'patch' in a:
        if state.get('patch_fails'): sys.exit(1)
        state['phase'] = 'outpost'; save()
elif 'clusterrolebinding' in a:
    if 'delete' in a:
        if state.get('delete_fails'): sys.exit(1)
        if not state.get('sticky'): state['binding'] = False
        save()
    else: print('clusterrolebinding/wiz-web-baseline' if state['binding'] else '')
elif a[:2] == ['-n', 'wiz-web'] and 'pods' in a:
    for p in state['pods']: print('|'.join([p['name'], p['uid'], p.get('deleting', ''), p['ready']]))
elif a[:2] == ['-n', 'wiz-web'] and 'pod' in a and 'get' in a:
    if 'serviceAccountToken' in a[-1]: print('token' if state['projected'] else '', end='')
    else:
        uid = 'ffffffff-0000-4000-8000-000000000000' if state.get('replaced') else state['pods'][0]['uid']
        print(uid + '|', end='')
elif 'exec' in a:
    if not state['projected']: sys.exit(2)
    if state.get('checker_broken'): sys.exit(2)
    print('allowed' if state['binding'] or state.get('allowed_anyway') else 'denied')
else: sys.exit(3)
"""


class OutpostTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name, body in (("kubectl", OUTPOST_KUBECTL), ("sleep", "#!/bin/sh\nexit 0\n")):
            tool = self.root / name
            tool.write_text(body)
            tool.chmod(0o700)
        self.env = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}", FIXTURE=str(self.root))

    def invoke(self, **state):
        base = {"phase": "baseline", "binding": True, "projected": True,
                "pods": [{"name": "web-5d8f7c9b4-abcde", "uid": POD_UID, "ready": "True"}]}
        base.update(state)
        (self.root / "state.json").write_text(json.dumps(base))
        reply = subprocess.run(["bash", OUTPOST], cwd=self.root, env=self.env, capture_output=True, text=True)
        return reply.returncode, reply.stdout, json.loads((self.root / "state.json").read_text())

    def test_same_pod_allowed_then_denied_and_phase_advanced(self):
        code, out, state = self.invoke()
        self.assertEqual(code, 0)
        self.assertEqual(out, f"pod web-5d8f7c9b4-abcde {POD_UID}\nbefore allowed\nafter denied\nphase outpost\n")
        self.assertEqual((state["phase"], state["binding"]), ("outpost", False))
        self.assertTrue(cluster.OUTPOST_EVIDENCE.fullmatch(out.strip()))

    def test_reruns_and_token_free_pods(self):
        code, out, _ = self.invoke(phase="outpost", binding=False)
        self.assertEqual((code, out.splitlines()[1:3]), (0, ["before denied", "after denied"]))
        code, out, _ = self.invoke(phase="outpost", binding=False, projected=False)
        self.assertEqual((code, out.splitlines()[1:3]), (0, ["before absent", "after absent"]))
        # Interrupted earlier run: binding gone, phase not yet advanced.
        code, out, state = self.invoke(binding=False)
        self.assertEqual((code, state["phase"]), (0, "outpost"))

    def test_failures_have_distinct_codes(self):
        cases = [
            ({"phase": ""}, 102), ({"phase": "initializing"}, 102), ({"phase": "outpost"}, 111),
            ({"pods": []}, 104), ({"pods": [{"name": "web-5d8f7c9b4-abcde", "uid": POD_UID, "ready": "False"}]}, 104),
            ({"pods": [{"name": "web-5d8f7c9b4-abcde", "uid": POD_UID, "ready": "True", "deleting": "2026-11-26T00:00:00Z"}]}, 104),
            ({"checker_broken": True}, 105), ({"delete_fails": True}, 106), ({"sticky": True}, 107),
            ({"allowed_anyway": True}, 108), ({"replaced": True}, 109), ({"patch_fails": True}, 110),
        ]
        for state, expected in cases:
            with self.subTest(state=state):
                code, out, after = self.invoke(**state)
                self.assertEqual(code, expected)
                self.assertEqual(out, "")
                if expected < 106:
                    self.assertTrue(after["binding"], "nothing may be revoked before the first observation")

    def test_runner_requires_complete_consistent_evidence(self):
        good = f"pod web-5d8f7c9b4-abcde {POD_UID}\nbefore allowed\nafter denied\nphase outpost"
        with tempfile.TemporaryDirectory() as directory, patch.object(cluster, "record") as record:
            with patch.object(cluster, "invoke", return_value=("a" * 32, good)) as remote:
                cluster.outpost(Path(directory))
                self.assertEqual(remote.call_args.args[2], ["outpost.sh"])
            self.assertIn("before revocation `allowed`, after revocation `denied`", record.call_args_list[1].args[0])
            for logs in (good.replace("after denied", "after allowed"), good.replace("before allowed", "before absent"),
                         good + "\nextra", "untrusted raw logs"):
                with self.subTest(logs=logs), patch.object(cluster, "invoke", return_value=("a" * 32, logs)):
                    with self.assertRaises(cluster.Failure):
                        cluster.outpost(Path(directory))


if __name__ == "__main__":
    unittest.main()
