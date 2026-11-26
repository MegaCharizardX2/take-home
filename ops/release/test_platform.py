"""Exercise baseline replay behavior against a local, recording kubectl double."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("platform.sh")


class PhaseTests(unittest.TestCase):
    def test_binding_creation_is_limited_to_initialization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / "kubectl"
            tool.write_text("""#!/usr/bin/env python3
import os, sys
from pathlib import Path
a=sys.argv[1:]; root=Path(os.environ['FIXTURE']); phase=root/'phase'; binding=root/'binding'
if 'configmap' in a and 'outpost-web-phase' in a:
    if 'get' in a: print(phase.read_text())
    elif 'create' in a: phase.write_text('initializing')
    elif 'patch' in a: phase.write_text('baseline')
    else: sys.exit(2)
elif 'clusterrolebinding' in a:
    if 'name' in a: print('clusterrolebinding/wiz-web-baseline' if binding.exists() else '')
    else: print(binding.read_text())
elif a[:3]==['create','-f','baseline-binding.yaml']:
    binding.write_text('outpost|rbac.authorization.k8s.io|ClusterRole|cluster-admin|ServiceAccount:wiz-web:web')
    with (root/'creates').open('a') as f:f.write('created\\n')
elif a[0]!='apply' and 'get' not in a:sys.exit(2)
""")
            tool.chmod(0o700)
            env = dict(os.environ, PATH=directory + ":" + os.environ["PATH"], FIXTURE=directory)
            def invoke():
                return subprocess.run(["bash", SCRIPT], cwd=root, env=env, capture_output=True).returncode
            (root / "phase").write_text("")
            self.assertEqual(invoke(), 0)
            self.assertEqual(invoke(), 0)
            self.assertEqual((root / "phase").read_text(), "baseline")
            (root / "binding").unlink()
            self.assertEqual(invoke(), 25)
            (root / "phase").write_text("outpost")
            self.assertEqual(invoke(), 0)
            self.assertEqual((root / "creates").read_text(), "created\n")
            self.assertFalse((root / "binding").exists())
