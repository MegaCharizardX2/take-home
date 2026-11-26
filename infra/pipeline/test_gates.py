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
        self.plan = {"planned_values": {"root_module": {"resources": [
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

    def test_expired_waivers_and_scanner_errors_block(self):
        with patch.object(plan_gate, "lab_exceptions_current", return_value=False), self.assertRaisesRegex(ValueError, "expired"):
            plan_gate.verify(self.report, self.plan, 1, self.allow)
        for status in (0, 125):
            with self.assertRaises(ValueError):
                plan_gate.verify(self.report, self.plan, status, self.allow)
        self.report["summary"]["parsing_errors"] = 1
        with self.assertRaises(ValueError):
            plan_gate.verify(self.report, self.plan, 1, self.allow)

    def test_exemption_cannot_widen_beyond_backup_account(self):
        scope = f"/subscriptions/{SUB}/resourceGroups/takehome-rg"
        account = scope + "/providers/Microsoft.Storage/storageAccounts/stoutpost123456789a"
        resources = {"azurerm_storage_account.backup": {"id": account}}
        after = {"name": "wiz-public-backup-baseline", "resource_id": account, "exemption_category": "Waiver",
                 "policy_assignment_id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn",
                 "policy_definition_reference_ids": ["StorageDisallowPublicAccess"], "expires_on": "2026-12-08T00:00:00Z"}
        change = {"type": "azurerm_resource_policy_exemption", "address": "azurerm_resource_policy_exemption.backup[0]",
                  "change": {"actions": ["create"], "after": after}}
        plan_gate.check_backup_changes({"resource_changes": [change]}, resources)
        for key, value in (("resource_id", scope), ("policy_definition_reference_ids", []), ("expires_on", None)):
            with self.subTest(key=key), patch.dict(after, {key: value}), self.assertRaises(ValueError):
                plan_gate.check_backup_changes({"resource_changes": [change]}, resources)
        with patch.dict(change, {"type": "azurerm_resource_group_policy_exemption"}), self.assertRaises(ValueError):
            plan_gate.check_backup_changes({"resource_changes": [change]}, resources)


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
