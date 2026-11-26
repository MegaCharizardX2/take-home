import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("backup-preflight.sh")


class BackupPreflight(unittest.TestCase):
    def test_step_a_is_only_for_existing_public_storage_without_a_cmk(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            terraform = folder / "terraform"
            terraform.write_text(
                '#!/bin/sh\ncase "$2" in\n'
                'state) cat "$STATE_LIST" ;;\n'
                'show) cat "$STATE_JSON" ;;\n'
                '*) exit 1 ;;\nesac\n'
            )
            terraform.chmod(0o700)
            state_list = folder / "resources"
            state_json = folder / "state.json"
            output = folder / "output"
            env = dict(os.environ, PATH=f"{folder}:{os.environ['PATH']}",
                       STATE_LIST=str(state_list), STATE_JSON=str(state_json), GITHUB_OUTPUT=str(output))
            resources = ["azurerm_disk_encryption_set.mongo", "azurerm_storage_account.backup",
                         "azurerm_key_vault_key.backup", "azurerm_role_assignment.backup_cmk"]
            for existing, public, key, stage, expected in (
                (True, True, [], None, "true"),       # legacy state
                (True, False, [], None, "false"),    # interrupted A, storage already private
                (True, False, [], "outpost", "false"),
                (True, True, [], "outpost", "false"),  # later drift
                (True, True, [{}], None, "false"),   # never remove an existing CMK
                (False, None, None, None, "false"),  # fresh account
            ):
                with self.subTest(existing=existing, public=public, key=key, stage=stage):
                    state_list.write_text("\n".join(resources if existing else resources[:1]) + "\n")
                    state_json.write_text(json.dumps({"values": {
                        "outputs": {"backup_stage": {"value": stage}} if stage else {},
                        "root_module": {"resources": [{
                            "address": "azurerm_storage_account.backup",
                            "values": {"public_network_access_enabled": public, "customer_managed_key": key},
                        }] if existing else []},
                    }}))
                    output.write_text("")
                    subprocess.run(["bash", str(SCRIPT), "outpost"], env=env,
                                   check=True, capture_output=True, text=True)
                    self.assertEqual(output.read_text(), f"private_first={expected}\n")
