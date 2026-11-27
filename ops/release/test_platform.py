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
DNS = {"to": [{"namespaceSelector": {}, "podSelector": {}}]}
MONGO = {"to": [{"ipBlock": {"cidr": "10.84.2.36/32"}}]}
API = {"to": [{"ipBlock": {"cidr": "10.86.0.1/32"}}, {"ipBlock": {"cidr": "10.84.2.0/27"}}]}

PLATFORM_KUBECTL = """#!/usr/bin/env python3
import os, sys
from pathlib import Path
a=sys.argv[1:]; root=Path(os.environ['FIXTURE']); phase=root/'phase'; binding=root/'binding'; policy=root/'transition'
with (root/'calls').open('a') as f: print(' '.join(a), file=f)
if 'configmap' in a and 'outpost-web-phase' in a:
    if 'get' in a: print(phase.read_text() if phase.exists() else '')
    elif 'create' in a: phase.write_text(a[-1].split('=')[-1])
    elif 'patch' in a: phase.write_text('outpost')
    else: sys.exit(2)
elif 'clusterrolebinding' in a:
    print('clusterrolebinding/wiz-web-baseline' if binding.exists() else '')
elif 'networkpolicy' in a:
    if 'delete' in a:
        if not (root/'sticky').exists(): policy.unlink(missing_ok=True)
    else: print('networkpolicy.networking.k8s.io/tasky-api-transition' if policy.exists() else '')
elif a[0]=='apply' and 'web-api-transition.yaml' in a:
    if (root/'apply-fails').exists(): sys.exit(1)
    policy.write_text('yes')
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

    def calls(self):
        return (self.root / "calls").read_text().splitlines()

    def test_setup_never_grants_cluster_admin(self):
        # Fresh hardened build: no phase record yet, so it starts in the Outpost phase.
        self.assertEqual(self.invoke(), 0)
        self.assertEqual((self.root / "phase").read_text(), "outpost")
        self.assertEqual(self.invoke(), 0)
        self.assertFalse((self.root / "binding").exists())
        self.assertNotIn("baseline-binding", "\n".join(self.calls()))
        self.assertNotIn("web-api-transition.yaml", "\n".join(self.calls()))

    def test_phases(self):
        cases = [("", True, 25), ("initializing", False, 0), ("initializing", True, 25),
                 ("baseline", True, 0), ("baseline", False, 0), ("outpost", False, 0), ("outpost", True, 29),
                 ("unknown", False, 30)]
        for phase, binding, code in cases:
            with self.subTest(phase=phase, binding=binding):
                for name in ("phase", "binding", "transition"):
                    (self.root / name).unlink(missing_ok=True)
                if phase:
                    (self.root / "phase").write_text(phase)
                if binding:
                    (self.root / "binding").write_text("yes")
                self.assertEqual(self.invoke(), code)
                if phase == "initializing" and code == 0:
                    self.assertEqual((self.root / "phase").read_text(), "outpost")
                if phase == "baseline":
                    # The live binding and the web API route stay for the outpost step's proof.
                    self.assertEqual((self.root / "binding").exists(), binding)
                    self.assertEqual((self.root / "phase").read_text(), "baseline")
                    self.assertTrue((self.root / "transition").exists())
                elif code == 0:
                    self.assertFalse((self.root / "transition").exists())

    def test_outpost_phase_never_reopens_the_web_api_route(self):
        (self.root / "phase").write_text("outpost")
        (self.root / "transition").write_text("yes")  # for example a stray manual apply
        self.assertEqual(self.invoke(), 0)
        self.assertFalse((self.root / "transition").exists())
        self.assertNotIn("web-api-transition.yaml", "\n".join(self.calls()))
        (self.root / "transition").write_text("yes")
        (self.root / "sticky").write_text("yes")
        self.assertEqual(self.invoke(), 20)

    def test_baseline_keeps_its_route_before_network_yaml_drops_the_old_inline_rule(self):
        (self.root / "phase").write_text("baseline")
        self.assertEqual(self.invoke(), 0)
        applies = [c for c in self.calls() if c.startswith("apply")]
        self.assertIn("web-api-transition.yaml", applies[1])
        self.assertIn("network.yaml", applies[2])
        (self.root / "apply-fails").write_text("yes")
        self.assertEqual(self.invoke(), 27)


# A fake cluster: web pod state, the binding, the phase record, the wiz-web network
# policies and the pod's own marker check (which needs a route to the API and answers
# from the binding, like the real authorizer).
OUTPOST_KUBECTL = r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
a = sys.argv[1:]; root = Path(os.environ['FIXTURE']); state = json.loads((root/'state.json').read_text())
def save(): (root/'state.json').write_text(json.dumps(state))
DNS = {'to': [{'namespaceSelector': {}, 'podSelector': {}}]}
MONGO = {'to': [{'ipBlock': {'cidr': '10.84.2.36/32'}}]}
API = {'to': [{'ipBlock': {'cidr': '10.86.0.1/32'}}, {'ipBlock': {'cidr': '10.84.2.0/27'}}]}
policies = state['policies']
def route(): return 'tasky-api-transition' in policies or API in policies.get('tasky', [])
with (root/'calls').open('a') as f: print(json.dumps(a), file=f)
if 'networkpolicy' in a:
    if 'delete' in a:
        if not state.get('sticky_policy'): policies.pop('tasky-api-transition', None)
        save()
    else:
        print(json.dumps({'items': [{'metadata': {'name': n}, 'spec': {'egress': e}} for n, e in policies.items()]}))
elif a[0] == 'apply':
    if state.get('apply_fails') or a[-1] != 'network.yaml': sys.exit(1)
    policies['tasky'] = [DNS, MONGO] + ([{}] if state.get('loose') else []); save()
elif 'outpost-web-phase' in a:
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
elif 'patch' in a and 'deployment' in a:
    if state.get('rotate_fails') or json.loads(a[-1]) != {'spec': {'template': {'spec': {'automountServiceAccountToken': False}}}}: sys.exit(1)
elif 'rollout' in a:
    if state.get('rollout_fails'): sys.exit(1)
elif 'exec' in a:
    if state.get('always_denied'): print('denied'); sys.exit(0)
    if not state['projected'] or not route(): sys.exit(2)
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
        (self.root / "calls").unlink(missing_ok=True)
        base = {"phase": "baseline", "binding": True, "projected": True,
                "pods": [{"name": "web-5d8f7c9b4-abcde", "uid": POD_UID, "ready": "True"}],
                "policies": {"default-deny": [], "tasky": [DNS, MONGO], "tasky-api-transition": [API]}}
        base.update(state)
        (self.root / "state.json").write_text(json.dumps(base))
        reply = subprocess.run(["bash", OUTPOST], cwd=self.root, env=self.env, capture_output=True, text=True)
        return reply.returncode, reply.stdout, json.loads((self.root / "state.json").read_text())

    def test_same_pod_allowed_then_denied_then_route_closed(self):
        code, out, state = self.invoke()
        self.assertEqual(code, 0)
        self.assertEqual(out, f"pod web-5d8f7c9b4-abcde {POD_UID}\nbefore allowed\nafter denied\nphase outpost\napi egress closed\n")
        self.assertEqual((state["phase"], state["binding"]), ("outpost", False))
        self.assertEqual(sorted(state["policies"]), ["default-deny", "tasky"])
        self.assertTrue(cluster.OUTPOST_EVIDENCE.fullmatch("\n".join(out.splitlines()[:3])))
        # The route closes only after the proof: the denial was observed through it.
        calls = (self.root / "calls").read_text().splitlines()
        self.assertGreater(min(i for i, c in enumerate(calls) if c.startswith('["apply"')),
                           max(i for i, c in enumerate(calls) if '"exec"' in c))

    def test_live_phase1_shape_closes_too(self):
        # Today's live cluster: the API route sits inline in tasky, with no transition policy.
        code, out, state = self.invoke(policies={"default-deny": [], "tasky": [DNS, MONGO, API]})
        self.assertEqual((code, out.splitlines()[1:3]), (0, ["before allowed", "after denied"]))
        self.assertNotIn(API, state["policies"]["tasky"])

    def test_reruns_and_token_free_pods(self):
        code, out, _ = self.invoke(phase="outpost", binding=False)
        self.assertEqual((code, out.splitlines()[1:3]), (0, ["before denied", "after denied"]))
        code, out, _ = self.invoke(phase="outpost", binding=False, projected=False)
        self.assertEqual((code, out.splitlines()[1:3]), (0, ["before absent", "after absent"]))
        # Rerun after the route closed, before Pipeline 2 replaced the token-bearing pod.
        code, out, _ = self.invoke(phase="outpost", binding=False, policies={"default-deny": [], "tasky": [DNS, MONGO]})
        self.assertEqual((code, out.splitlines()[1:3]), (0, ["before unreachable", "after unreachable"]))
        # Interrupted earlier run: binding gone, phase not yet advanced.
        code, out, state = self.invoke(binding=False)
        self.assertEqual((code, state["phase"]), (0, "outpost"))

    def test_failures_have_distinct_codes(self):
        cases = [
            ({"phase": ""}, 102), ({"phase": "initializing"}, 102), ({"phase": "outpost"}, 111),
            ({"pods": []}, 104), ({"pods": [{"name": "web-5d8f7c9b4-abcde", "uid": POD_UID, "ready": "False"}]}, 104),
            ({"pods": [{"name": "web-5d8f7c9b4-abcde", "uid": POD_UID, "ready": "True", "deleting": "2026-11-26T00:00:00Z"}]}, 104),
            ({"always_denied": True}, 105), ({"checker_broken": True}, 105), ({"delete_fails": True}, 106), ({"sticky": True}, 107),
            ({"allowed_anyway": True}, 108), ({"replaced": True}, 109), ({"patch_fails": True}, 110),
            ({"rotate_fails": True}, 115), ({"rollout_fails": True}, 116), ({"apply_fails": True}, 112), ({"sticky_policy": True}, 113), ({"loose": True}, 113),
            # Baseline phase without any API route: no proof is possible, so nothing is revoked.
            ({"policies": {"default-deny": [], "tasky": [DNS, MONGO]}}, 105),
        ]
        for state, expected in cases:
            with self.subTest(state=state):
                code, out, after = self.invoke(**state)
                self.assertEqual(code, expected)
                if expected in (110, 112, 113, 115, 116):
                    self.assertEqual(out.splitlines()[1:], ["before allowed", "after denied"])
                    reply = dict(provisioningState="Succeeded", exitCode=code, logs=out)
                    with patch.object(cluster, "record") as record, self.assertRaises(cluster.CheckFailure):
                        cluster.result(json.dumps(reply), outpost_proof=True)
                    self.assertIn("after revocation `denied`", record.call_args.args[0])
                    for bad in (out + "untrusted", out.replace("after denied", "after invalid")):
                        with patch.object(cluster, "record") as record, self.assertRaises(cluster.CheckFailure):
                            cluster.result(json.dumps(dict(reply, logs=bad)), outpost_proof=True)
                        record.assert_not_called()
                elif expected in (106, 107, 108, 109) or state.get("always_denied"):
                    first = "denied" if state.get("always_denied") else "allowed"
                    self.assertEqual(out.splitlines()[1:], ["before " + first])
                    with patch.object(cluster, "record") as record, self.assertRaises(cluster.CheckFailure):
                        cluster.result(json.dumps(dict(provisioningState="Succeeded", exitCode=code, logs=out)), outpost_proof=True)
                    self.assertIn("after observation incomplete", record.call_args.args[0])
                else:
                    self.assertEqual(out, "")
                if expected in (104, 105):
                    self.assertTrue(after["binding"], "nothing may be revoked before the first observation")

    def test_jq_preflight_preserves_live_binding(self):
        tool = self.root / "jq"
        tool.write_text("#!/bin/sh\nexit 1\n")
        tool.chmod(0o700)
        code, out, state = self.invoke()
        self.assertEqual((code, out, state["binding"]), (114, "", True))

    def test_runner_requires_complete_consistent_evidence(self):
        good = f"pod web-5d8f7c9b4-abcde {POD_UID}\nbefore allowed\nafter denied\nphase outpost\napi egress closed"
        with tempfile.TemporaryDirectory() as directory, patch.object(cluster, "record") as record, \
                patch.object(cluster, "scan") as scanner:
            with patch.object(cluster, "invoke", return_value=("a" * 32, good)) as remote:
                cluster.outpost(Path(directory))
                self.assertEqual(remote.call_args.args[2], ["outpost.sh", "network.yaml"])
            scanner.assert_called_once()
            # The attached policy gives web no API route (Traefik's own policy still needs one).
            web = (Path(directory) / "network.yaml").read_text().split("name: default-deny, namespace: traefik")[0]
            self.assertNotIn("10.86.0.1", web)
            self.assertIn("before revocation `allowed`, after revocation `denied`", record.call_args_list[1].args[0])
            rerun = good.replace("before allowed\nafter denied", "before unreachable\nafter unreachable")
            with patch.object(cluster, "invoke", return_value=("a" * 32, rerun)):
                cluster.outpost(Path(directory))
            for logs in (good.replace("after denied", "after allowed"), good.replace("before allowed", "before absent"),
                         good.replace("before allowed", "before unreachable"), good.replace("\napi egress closed", ""),
                         good + "\nextra", "untrusted raw logs"):
                with self.subTest(logs=logs), patch.object(cluster, "invoke", return_value=("a" * 32, logs)):
                    with self.assertRaises(cluster.Failure):
                        cluster.outpost(Path(directory))


class ManifestTests(unittest.TestCase):
    def test_only_the_baseline_transition_policy_routes_web_to_the_api(self):
        root = Path(__file__).resolve().parents[2] / "k8s/platform"
        self.assertNotIn("10.86.0.1", (root / "network.yaml").read_text().split("name: default-deny, namespace: traefik")[0])
        transition = (root / "web-api-transition.yaml").read_text()
        self.assertIn("name: tasky-api-transition", transition)
        self.assertIn("10.86.0.1/32", transition)


if __name__ == "__main__":
    unittest.main()
