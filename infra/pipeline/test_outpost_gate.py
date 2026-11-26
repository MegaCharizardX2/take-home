"""Outpost-stage plan gate: one-way stage, retired exceptions and the remediated-state contract."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import plan_gate

ROOT = Path(__file__).resolve().parents[2]
SUB = "00000000-0000-0000-0000-000000000001"
ACTOR = "azurerm_container_registry.images"
RG = f"/subscriptions/{SUB}/resourceGroups/takehome-rg"
ACCOUNT = RG + "/providers/Microsoft.Storage/storageAccounts/stoutpost123456789a"
CMK_ID = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-backup-cmk"
# A synthetic, globally routable home address (the gate rejects documentation ranges).
HOME = "1.2.3.4/32"


def outpost_resources():
    """Planned values for the remediated resources, shaped like `terraform show -json`."""
    return {
        ACTOR: {"sku": "Basic"},
        "azurerm_storage_account.backup": {
            "id": ACCOUNT, "public_network_access_enabled": False, "allow_nested_items_to_be_public": False,
            "shared_access_key_enabled": False, "identity": [{"type": "UserAssigned", "identity_ids": [CMK_ID]}],
            "customer_managed_key": [{"key_vault_key_id": "https://kv-outpost-123456789a.vault.azure.net/keys/backup-cmk",
                                      "user_assigned_identity_id": CMK_ID}]},
        "azurerm_storage_container.backups": {"container_access_type": "private"},
        'azurerm_private_endpoint.lab["blob"]': {"name": "pe-outpost-blob"},
        "azurerm_network_interface.mongo": {"ip_configuration": [{"name": "mongo", "public_ip_address_id": None}]},
        "azurerm_public_ip.ingress": {"name": "pip-ingress"},
        "azurerm_public_ip.nat": {"name": "pip-nat"},
        'azurerm_network_security_rule.mongo["ssh-deny"]': {
            "name": "mongo-ssh-deny", "network_security_group_name": "nsg-mongo", "access": "Deny",
            "direction": "Inbound", "destination_port_range": "22"},
        'azurerm_role_assignment.lab["vm_writer"]': {"role_definition_name": "Lab Backup Writer",
                                                     "scope": ACCOUNT + "/blobServices/default/containers/backups"},
        "azapi_resource.aks": {"body": {"properties": {"apiServerAccessProfile": {
            "enableVnetIntegration": True, "enablePrivateCluster": False, "authorizedIPRanges": [HOME]}}}},
    }


def plan_of(resources, stage="outpost", changes=()):
    return {"variables": {"backup_stage": {"value": stage}}, "resource_changes": list(changes),
            "planned_values": {"root_module": {"resources": [
                {"address": a, "mode": "managed", "values": v} for a, v in resources.items()]}}}


def report_of(address=ACTOR, check="CKV_AZURE_139", count=1):
    return {"check_type": "terraform_plan",
            "summary": {"failed": 1, "passed": 1, "skipped": 0, "resource_count": count, "parsing_errors": 0},
            "results": {"failed_checks": [{"resource_address": address, "check_id": check}]}}


class OutpostGateTests(unittest.TestCase):
    def setUp(self):
        self.allow = plan_gate.exceptions(ROOT)

    def verify(self, plan, report=None):
        with patch.object(plan_gate, "lab_exceptions_current", return_value=True):
            return plan_gate.verify(report or report_of(), plan, 1, self.allow)

    def test_outpost_retired_the_phase1_exceptions(self):
        retired = {"CKV_AZURE_10", "CKV_AZURE_119", "CKV2_AZURE_39", "CKV_AZURE_59", "CKV_AZURE_34",
                   "CKV2_AZURE_8", "CKV2_AZURE_47", "CKV_AZURE_190", "CKV2_AZURE_1"}
        self.assertFalse(retired & {rule for rule, _ in self.allow})
        for rule, address in (("CKV_AZURE_59", "azurerm_storage_account.backup"),
                              ("CKV2_AZURE_39", "azurerm_network_interface.mongo"),
                              ("CKV2_AZURE_1", "azurerm_storage_account.backup")):
            with self.subTest(rule=rule), self.assertRaisesRegex(ValueError, "Unapproved"):
                self.verify(plan_of(outpost_resources()), report_of(address, rule))
        trivy = (ROOT / ".trivyignore.yaml").read_text()
        self.assertNotIn("KSV-0036", trivy)
        self.assertNotIn("KSV-0111", trivy)
        for path in ("storage.tf", "mongo.tf"):
            self.assertNotIn("trivy:ignore", (ROOT / "infra" / path).read_text())

    def test_phase1_stages_are_refused(self):
        for stage in ("closed", "waiver", "public", None):
            with self.subTest(stage=stage), self.assertRaisesRegex(ValueError, "Phase-1"):
                self.verify(plan_of({ACTOR: {"sku": "Basic"}}, stage=stage))

    def test_nsg_findings_follow_only_mirrored_or_retired_rules(self):
        nsg = 'azurerm_network_security_group.lab["mongo"]'
        rules = {
            'azurerm_network_security_rule.mongo["aks"]': {"name": "mongo-aks", "network_security_group_name": "nsg-mongo"},
            'azurerm_network_security_rule.mongo["ssh-deny"]': {"name": "mongo-ssh-deny", "network_security_group_name": "nsg-mongo",
                                                               "access": "Deny", "direction": "Inbound", "destination_port_range": "22"},
        }
        deleted = {"type": "azurerm_network_security_rule", "address": "azurerm_network_security_rule.ssh",
                   "change": {"actions": ["delete"], "after": None,
                              "before": {"name": "Internet-to-mongo-ssh", "network_security_group_name": "nsg-mongo"}}}

        def scan(inline, check="CKV_AZURE_10", changes=()):
            resources = dict(copy.deepcopy(rules))
            resources[nsg] = {"name": "nsg-mongo", "security_rule": [{"name": n} for n in inline]}
            return self.verify(plan_of(resources, changes=changes), report_of(nsg, check, 3))
        # Outpost's own plan: the refresh still lists the Internet SSH rule it deletes.
        self.assertEqual(scan(["mongo-aks", "Internet-to-mongo-ssh"], changes=[deleted]), 1)
        for inline, changes in ((["mongo-aks", "Internet-to-mongo-ssh"], ()),
                                (["mongo-aks", "Internet-to-mongo-ssh", "rogue-rdp"], [deleted]),
                                ([], [deleted])):
            with self.subTest(inline=inline), self.assertRaisesRegex(ValueError, "Unapproved"):
                scan(inline, changes=changes)

    def test_public_storage_and_any_exemption_write_are_refused(self):
        exemption = {"type": "azurerm_resource_policy_exemption", "address": "azurerm_resource_policy_exemption.backup[0]",
                     "change": {"actions": ["create"], "after": {"name": "wiz-public-backup-baseline", "resource_id": ACCOUNT}}}
        arm_exemption = {"type": "azapi_resource", "address": "azapi_resource.exemption",
                         "change": {"actions": ["update"], "after": {"type": "Microsoft.Authorization/policyExemptions@2022-07-01-preview"}}}
        account = {"type": "azurerm_storage_account", "address": "azurerm_storage_account.backup",
                   "change": {"actions": ["update"], "after": {"allow_nested_items_to_be_public": False,
                                                               "public_network_access_enabled": False}}}
        container = {"type": "azurerm_storage_container", "address": "azurerm_storage_container.backups",
                     "change": {"actions": ["update"], "after": {"container_access_type": "private"}}}
        self.assertEqual(self.verify(plan_of(outpost_resources(), changes=[account, container])), 1)
        for change in (exemption, arm_exemption):
            with self.subTest(change=change["address"]), self.assertRaisesRegex(ValueError, "exemption"):
                self.verify(plan_of(outpost_resources(), changes=[change]))
        for after, change in (({"allow_nested_items_to_be_public": True}, account),
                              ({"public_network_access_enabled": True}, account),
                              ({"container_access_type": "container"}, container),
                              ({"container_access_type": "blob"}, container)):
            bad = copy.deepcopy(change)
            bad["change"]["after"].update(after)
            with self.subTest(after=after), self.assertRaisesRegex(ValueError, "public storage"):
                self.verify(plan_of(outpost_resources(), changes=[bad]))
        # Deleting the Phase-1 waiver is exactly what the Outpost plan does.
        removal = dict(exemption, change={"actions": ["delete"], "after": None, "before": exemption["change"]["after"]})
        self.assertEqual(self.verify(plan_of(outpost_resources(), changes=[removal])), 1)

    def test_outpost_state_contract(self):
        self.assertEqual(self.verify(plan_of(outpost_resources())), 1)
        account, aks = "azurerm_storage_account.backup", "azapi_resource.aks"

        def profile(**changes):
            return lambda r: r[aks]["body"]["properties"]["apiServerAccessProfile"].update(changes)
        mutations = {
            "public network": lambda r: r[account].update(public_network_access_enabled=True),
            "nested public": lambda r: r[account].update(allow_nested_items_to_be_public=True),
            "shared key": lambda r: r[account].update(shared_access_key_enabled=True),
            "no cmk": lambda r: r[account].update(customer_managed_key=[]),
            "other key": lambda r: r[account]["customer_managed_key"][0].update(key_vault_key_id="https://kv/keys/other"),
            "other identity": lambda r: r[account]["customer_managed_key"][0].update(user_assigned_identity_id=RG + "/x/id-mongo"),
            "no private endpoint": lambda r: r.pop('azurerm_private_endpoint.lab["blob"]'),
            "public container": lambda r: r["azurerm_storage_container.backups"].update(container_access_type="container"),
            "nic public ip": lambda r: r["azurerm_network_interface.mongo"]["ip_configuration"][0].update(
                public_ip_address_id=RG + "/providers/Microsoft.Network/publicIPAddresses/pip-mongo"),
            "vm public ip": lambda r: r.update({"azurerm_public_ip.mongo": {"name": "pip-mongo"}}),
            "ssh allow": lambda r: r['azurerm_network_security_rule.mongo["ssh-deny"]'].update(access="Allow"),
            "ssh range": lambda r: r.update({"azurerm_network_security_rule.wide": {
                "access": "Allow", "direction": "Inbound", "destination_port_ranges": ["20-30"]}}),
            "any port": lambda r: r.update({"azurerm_network_security_rule.any": {
                "access": "Allow", "direction": "Inbound", "destination_port_range": "*"}}),
            "vm contributor": lambda r: r.update({'azurerm_role_assignment.lab["vm_compute"]': {
                "role_definition_name": "Virtual Machine Contributor", "scope": RG}}),
            "blob contributor": lambda r: r.update({'azurerm_role_assignment.lab["vm_backup"]': {
                "role_definition_name": "Storage Blob Data Contributor", "scope": ACCOUNT}}),
            "writer scope": lambda r: r['azurerm_role_assignment.lab["vm_writer"]'].update(scope=ACCOUNT),
            "writer role": lambda r: r['azurerm_role_assignment.lab["vm_writer"]'].update(role_definition_name="Owner"),
            "exemption kept": lambda r: r.update({"azurerm_resource_policy_exemption.backup[0]": {"name": "wiz-public-backup-baseline"}}),
            "open api": profile(authorizedIPRanges=[]),
            "missing ranges": profile(authorizedIPRanges=None),
            "two ranges": profile(authorizedIPRanges=[HOME, "5.6.7.8/32"]),
            "wide range": profile(authorizedIPRanges=["1.2.3.0/24"]),
            "private range": profile(authorizedIPRanges=["10.84.0.4/32"]),
            "documentation range": profile(authorizedIPRanges=["198.51.100.7/32"]),
            "no vnet integration": profile(enableVnetIntegration=False),
            "private cluster": profile(enablePrivateCluster=True),
        }
        for name, mutate in mutations.items():
            resources = copy.deepcopy(outpost_resources())
            mutate(resources)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "^Refusing"):
                self.verify(plan_of(resources))
        # Older AzAPI stores the body as a JSON string; targeted plans omit resources.
        resources = outpost_resources()
        resources[aks]["body"] = json.dumps(resources[aks]["body"])
        self.assertEqual(self.verify(plan_of(resources)), 1)
        self.assertEqual(self.verify(plan_of({ACTOR: {"sku": "Basic"}})), 1)

    def test_refusals_never_echo_plan_values(self):
        resources = outpost_resources()
        resources["azapi_resource.aks"]["body"]["properties"]["apiServerAccessProfile"]["authorizedIPRanges"] = ["10.1.2.3/32"]
        with self.assertRaises(ValueError) as caught:
            self.verify(plan_of(resources))
        self.assertNotIn("10.1.2.3", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
