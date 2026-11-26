import unittest

import error_excerpt

PLAN_LOG = """\
random_id.instance: Refreshing state... [id=3E5sdw]
azurerm_key_vault.lab: Refreshing state... [id=/subscriptions/x/resourceGroups/takehome-rg/providers/Microsoft.KeyVault/vaults/kv-outpost-dc4e6c7869]

Warning: Deprecated attribute

  on storage.tf line 40, in resource "azurerm_storage_account" "backup":
  40:   queue_properties {

Error: retrieving Key "backup-cmk": keyvault.BaseClient#GetKey: Failure responding to request: StatusCode=403

  with azurerm_key_vault_key.backup,
  on keys.tf line 1, in resource "azurerm_key_vault_key" "backup":
   1: resource "azurerm_key_vault_key" "backup" {

Caller ops@example.com used token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl with key=abc123
admin key ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDdemo wiz-mongo

Error: Invalid value for variable

  on variables.tf line 1:
   1: variable "ssh_public_key" {

Supply a single OpenSSH RSA public key.
"""


class ErrorExcerptTests(unittest.TestCase):
    def test_keeps_only_error_blocks(self):
        lines = error_excerpt.excerpt(PLAN_LOG)
        text = "\n".join(lines)
        self.assertTrue(lines[0].startswith("Error: retrieving Key"))
        self.assertIn("with azurerm_key_vault_key.backup,", text)
        self.assertIn("on keys.tf line 1", text)
        self.assertIn("Supply a single OpenSSH RSA public key.", text)
        self.assertNotIn("Refreshing state", text)
        self.assertNotIn("Deprecated attribute", text)

    def test_redacts_values(self):
        text = "\n".join(error_excerpt.excerpt(PLAN_LOG))
        for leaked in ("ops@example.com", "eyJhbGci", "AAAAB3Nza", "abc123"):
            self.assertNotIn(leaked, text)
        self.assertIn("<email redacted>", text)
        self.assertIn("ssh-<key redacted>", text)

    def test_redacts_connection_strings_and_long_blobs(self):
        line = error_excerpt.redact("uri mongodb://tasky:pw@mongo.wiz.internal:27017/?authSource=admin blob " + "A" * 80)
        self.assertNotIn("tasky:pw", line)
        self.assertNotIn("A" * 80, line)

    def test_caps_output(self):
        log = "Error: many\n" + "\n".join(f"line {i}" for i in range(500))
        lines = error_excerpt.excerpt(log)
        self.assertEqual(len(lines), error_excerpt.MAX_LINES + 1)
        self.assertIn("more lines omitted", lines[-1])

    def test_no_error_block(self):
        self.assertEqual(error_excerpt.excerpt("Plan: 1 to add, 0 to change, 0 to destroy.\n"), [])


if __name__ == "__main__":
    unittest.main()
