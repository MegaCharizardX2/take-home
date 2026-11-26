from datetime import date, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scanner_policy import ROOT, render


class ScannerPolicyTests(unittest.TestCase):
    def test_changing_the_one_date_changes_all_scanners(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "infra").mkdir()
            (root / "policy").symlink_to(ROOT / "policy")
            (root / "infra/public-access.tf").symlink_to(ROOT / "infra/public-access.tf")
            for expiry in (date(2030, 3, 4), date(2031, 5, 6)):
                (root / "infra/lab-expiry.txt").write_text(f"{expiry}\n")
                before = expiry - timedelta(days=1)
                self.assertIn("CKV_AZURE_160:", render("checkov.yaml", root, before))
                self.assertIn(f"expired_at: {expiry}", render("trivy.yaml", root, before))
                self.assertIn(f'#trivy:ignore:AZU-0047:exp:{expiry}\nresource "azurerm_network_security_rule" "ingress"',
                              render("public-access.tf", root, before))
                for today in (expiry, expiry + timedelta(days=1)):
                    self.assertEqual(render("checkov.yaml", root, today), "skip-check: []\n")
                    self.assertEqual(render("trivy.yaml", root, today), "misconfigurations: []\n")
                    self.assertEqual(render("public-access.tf", root, today), (root / "infra/public-access.tf").read_text())
