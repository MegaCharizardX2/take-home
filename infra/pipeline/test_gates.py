import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import plan_gate

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SUB = "00000000-0000-0000-0000-000000000001"
ACTOR = "azurerm_container_registry.images"
EXPECTED = ["PASS binding annotation", "PASS ordinary pod admitted", "PASS privileged pod denied by deny-privileged"]


class PlanGateTests(unittest.TestCase):
    def setUp(self):
        self.allow = plan_gate.exceptions(ROOT)
        self.plan = {"variables": {"backup_stage": {"value": "outpost"}}, "planned_values": {"root_module": {"resources": [
            {"address": ACTOR, "mode": "managed", "values": {"sku": "Basic"}}
        ]}}}
        self.report = {"check_type": "terraform_plan",
                       "summary": {"failed": 1, "passed": 1, "skipped": 0, "resource_count": 1, "parsing_errors": 0},
                       "results": {"failed_checks": [{"resource_address": ACTOR, "check_id": "CKV_AZURE_139"}]}}

    def test_only_reviewed_address_and_rule_pass(self):
        with patch.object(plan_gate, "lab_exceptions_current", return_value=True):
            self.assertEqual(plan_gate.verify(self.report, self.plan, 1, self.allow), 1)
        for key, value in (("resource_address", "azurerm_container_registry.other"), ("check_id", "CKV_AZURE_137")):
            with self.subTest(key=key):
                bad = copy.deepcopy(self.report)
                bad["results"]["failed_checks"][0][key] = value
                with self.assertRaisesRegex(ValueError, "Unapproved"):
                    plan_gate.verify(bad, self.plan, 1, self.allow)

    def test_nsg_findings_follow_only_mirrored_reviewed_rules(self):
        nsg = 'azurerm_network_security_group.lab["nodes"]'
        rules = {
            "azurerm_network_security_rule.ingress": {"name": "Internet-to-ingress", "network_security_group_name": "nsg-nodes"},
            "azurerm_network_security_rule.nodes_other": {"name": "nodes-other", "network_security_group_name": "nsg-nodes"},
        }
        def scan(inline, check="CKV_AZURE_160"):
            resources = [{"address": a, "mode": "managed", "values": v} for a, v in rules.items()]
            resources.append({"address": nsg, "mode": "managed",
                              "values": {"name": "nsg-nodes", "security_rule": [{"name": n} for n in inline]}})
            plan = {"variables": {"backup_stage": {"value": "outpost"}},
                    "planned_values": {"root_module": {"resources": resources}}}
            report = {"check_type": "terraform_plan",
                      "summary": {"failed": 1, "passed": 1, "skipped": 0, "resource_count": 3, "parsing_errors": 0},
                      "results": {"failed_checks": [{"resource_address": nsg, "check_id": check}]}}
            with patch.object(plan_gate, "lab_exceptions_current", return_value=True):
                return plan_gate.verify(report, plan, 1, self.allow)
        self.assertEqual(scan(["Internet-to-ingress", "nodes-other"]), 1)
        for inline, check in ((["Internet-to-ingress", "rogue-rdp"], "CKV_AZURE_160"),
                              ([], "CKV_AZURE_160"),
                              (["Internet-to-ingress"], "CKV_AZURE_9")):
            with self.subTest(inline=inline, check=check), self.assertRaisesRegex(ValueError, "Unapproved"):
                scan(inline, check)

    def test_expired_waivers_and_scanner_errors_block(self):
        with patch.object(plan_gate, "lab_exceptions_current", return_value=False), self.assertRaisesRegex(ValueError, "expired"):
            plan_gate.verify(self.report, self.plan, 1, self.allow)
        for status in (0, 125):
            with self.assertRaises(ValueError):
                plan_gate.verify(self.report, self.plan, status, self.allow)
        self.report["summary"]["parsing_errors"] = 1
        with self.assertRaises(ValueError):
            plan_gate.verify(self.report, self.plan, 1, self.allow)

class PanelTests(unittest.TestCase):
    def test_remote_protocol_and_attribution(self):
        # This executable records arguments locally. No cluster or workflow runs.
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            k = p / "kubectl"
            k.write_text("""#!/usr/bin/env python3
import json,os,sys
a=sys.argv[1:]; mode=os.environ['CASE']; trace=os.environ['TRACE']
with open(trace,'a') as f: print(json.dumps(a),file=f)
if 'get' in a and 'clusterrolebinding' in a: print('outpost|rbac.authorization.k8s.io|ClusterRole|view|'+('bound' if mode=='foreign' else 'empty')+'|12')
elif 'annotate' in a: pass
elif 'deployment' in a: print('acroutpost123456789a.azurecr.io/tasky@sha256:'+'a'*64)
elif 'get' in a:
 print('azurepolicy-demo|/subscriptions/'+os.environ['SUB']+'/resourceGroups/takehome-rg/providers/Microsoft.ContainerService/managedClusters/aks-outpost/providers/Microsoft.Authorization/policyAssignments/deny-privileged|/providers/Microsoft.Authorization/policyDefinitions/95edb821-ddaf-4404-9732-666045e056b4|deny')
elif 'run' in a and '--dry-run=server' in a:
 if '"privileged":true' in ' '.join(a) and mode!='admitted':
  print('admission webhook "validation.gatekeeper.sh" denied the request: ['+('other' if mode=='wrong' else 'azurepolicy-demo')+'] Privileged container is not allowed',file=sys.stderr);sys.exit(1)
else: sys.exit(3)
""")
            k.chmod(0o755)
            trace = p / "trace"
            for case in ("expected", "wrong", "admitted", "foreign"):
                trace.write_text("")
                env = dict(os.environ, PATH=tmp + ":" + os.environ["PATH"], CASE=case, TRACE=str(trace), SUB=SUB)
                run = subprocess.run(["bash", HERE / "panel-demo.sh", SUB, "42-1"], capture_output=True, text=True, env=env)
                calls = [json.loads(row) for row in trace.read_text().splitlines()]
                self.assertEqual(run.returncode == 0, case == "expected")
                if case == "expected":
                    self.assertEqual(run.stdout.splitlines(), EXPECTED)
                    pods = [a for a in calls if "run" in a]
                    self.assertEqual(len(pods), 2)
                    self.assertEqual([s.replace('"privileged":true', '"privileged":false') for s in pods[1]], pods[0])
                if case == "foreign":
                    self.assertFalse(any("annotate" in a for a in calls))

    def test_host_rejects_missing_exit_and_never_prints_raw_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "result"
            for code in (0, None, 1, "0"):
                file.write_text(json.dumps({"provisioningState": "Succeeded", "exitCode": code, "id": "fixture",
                                            "logs": "private diagnostic\n" + "\n".join(EXPECTED)}))
                run = subprocess.run(["python3", HERE / "panel-result.py", file], capture_output=True, text=True)
                self.assertEqual(run.returncode == 0, code == 0)
                self.assertNotIn("private diagnostic", run.stdout + run.stderr)
