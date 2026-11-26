"""Accept only Checkov plan exceptions for the exact reviewed root resource,
and only plans that keep the Outpost remediation in place."""

import datetime
import ipaddress
import json
from pathlib import Path
import re
import sys


ENTRY = re.compile(
    r"\s*- '(CKV2?_AZURE_\d+):([\w-]+)\\\.tf\$'\s+# \[(\w+)\.(\w+)\] \S.*"
)
STAGE = "outpost"
# Roles the Phase-1 baseline gave the database VM. Nothing in the lab needs them now.
RETIRED_ROLES = {"virtual machine contributor", "storage blob data contributor"}
# Traefik's frontend and the NAT gateway's egress address are the only public IPs.
PUBLIC_IPS = {"azurerm_public_ip.ingress", "azurerm_public_ip.nat"}


def exceptions(root):
    pairs = set()
    for line in (root / ".checkov.yaml").read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#") or line.strip() == "skip-check:":
            continue
        match = ENTRY.fullmatch(line)
        if not match:
            raise ValueError("Invalid file-scoped exception or missing resource address")
        rule, filename, kind, name = match.groups()
        source = (root / "infra" / (filename + ".tf")).read_text()
        declaration = rf'^resource\s+"{kind}"\s+"{name}"\s*\{{'
        if not re.search(declaration, source, re.MULTILINE):
            raise ValueError("Exception resource is absent from its approved file")
        pairs.add((rule, f"{kind}.{name}"))
    return pairs


def check_stage(plan):
    """Outpost is one-way: replaying a Phase-1 stage would reopen the weaknesses."""
    if plan.get("variables", {}).get("backup_stage", {}).get("value") != STAGE:
        raise ValueError("Refusing a Phase-1 stage: only the outpost stage can be planned")


def check_backup_changes(plan, resources):
    """Refuse public storage and any policy exemption write in every plan."""
    for change in plan.get("resource_changes", []):
        operation = change["change"]
        if not {"create", "update"}.intersection(operation["actions"]):
            continue
        value = operation["after"] or {}
        kind = change["type"]
        opens_account = kind == "azurerm_storage_account" and (
            value.get("allow_nested_items_to_be_public") is not False or value.get("public_network_access_enabled") is not False)
        opens_container = kind == "azurerm_storage_container" and value.get("container_access_type") != "private"
        if opens_account or opens_container:
            raise ValueError("Refusing public storage in the outpost stage")
        is_arm_exemption = (kind.startswith("azapi_") and
                            str(value.get("type", "")).split("@")[0].lower() == "microsoft.authorization/policyexemptions")
        if kind.endswith("_policy_exemption") or is_arm_exemption:
            raise ValueError("Refusing a policy exemption in the outpost stage")


def _body(values):
    body = values.get("body")
    if isinstance(body, str):
        body = json.loads(body)
    return body if isinstance(body, dict) else {}


def _public_slash32(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=True)
    except (TypeError, ValueError):
        return False
    return network.version == 4 and network.prefixlen == 32 and network.network_address.is_global


def _opens_ssh(rule):
    if rule.get("access") != "Allow" or rule.get("direction") != "Inbound":
        return False
    ports = [rule.get("destination_port_range")] + list(rule.get("destination_port_ranges") or [])
    for port in filter(None, ports):
        if port == "*":
            return True
        low, _, high = str(port).partition("-")
        if low.isdigit() and int(low) <= 22 <= int(high or low):
            return True
    return False


def check_outpost_state(resources):
    """Each remediated resource that is in the plan must stay remediated.

    The checks are presence-conditional so targeted bootstrap plans still pass.
    Failures name the control only: plan values can contain private data.
    """
    for address, value in resources.items():
        kind = address.split(".")[0]
        if kind.endswith("_policy_exemption"):
            raise ValueError("Refusing a plan that keeps a policy exemption")
        if kind == "azurerm_public_ip" and address not in PUBLIC_IPS:
            raise ValueError("Refusing a public IP outside ingress and NAT egress")
        if kind == "azurerm_network_interface" and any(
                (config or {}).get("public_ip_address_id") for config in value.get("ip_configuration") or []):
            raise ValueError("Refusing a public IP on a network interface")
        # Standalone rules only: an NSG's inline list is a refreshed mirror that still
        # shows rules this plan deletes. Unknown inline rules fail in mirrored_rules.
        if kind == "azurerm_network_security_rule" and _opens_ssh(value):
            raise ValueError("Refusing an inbound SSH allow rule")
        if kind == "azurerm_role_assignment" and str(value.get("role_definition_name", "")).lower() in RETIRED_ROLES:
            raise ValueError("Refusing a retired broad data or compute role")
    account = resources.get("azurerm_storage_account.backup")
    if account is not None:
        keys = account.get("customer_managed_key") or [{}]
        identity = (account.get("identity") or [{}])[0] or {}
        key = keys[0] or {}
        if (account.get("public_network_access_enabled") is not False
                or account.get("allow_nested_items_to_be_public") is not False
                or account.get("shared_access_key_enabled") is not False
                or not re.search(r"/keys/backup-cmk$", str(key.get("key_vault_key_id", "")))
                or not str(key.get("user_assigned_identity_id", "")).lower().endswith("/userassignedidentities/id-backup-cmk")
                or identity.get("type") != "UserAssigned"):
            raise ValueError("Refusing a backup account without private access and the backup CMK")
        if 'azurerm_private_endpoint.lab["blob"]' not in resources:
            raise ValueError("Refusing a backup account without its Blob private endpoint")
    container = resources.get("azurerm_storage_container.backups")
    if container is not None and container.get("container_access_type") != "private":
        raise ValueError("Refusing a public backup container")
    writer = resources.get('azurerm_role_assignment.lab["vm_writer"]')
    # The scope is unknown (absent) only when the container is created in the same plan.
    if writer is not None and (writer.get("role_definition_name") != "Lab Backup Writer"
                               or not str(writer.get("scope", "/containers/backups")).lower().endswith("/containers/backups")):
        raise ValueError("Refusing a database VM grant other than the container-scoped backup writer")
    aks = resources.get("azapi_resource.aks")
    if aks is not None:
        profile = _body(aks).get("properties", {}).get("apiServerAccessProfile", {})
        ranges = profile.get("authorizedIPRanges")
        if (profile.get("enableVnetIntegration") is not True or profile.get("enablePrivateCluster") is True
                or not isinstance(ranges, list) or len(ranges) != 1 or not _public_slash32(ranges[0])):
            raise ValueError("Refusing an AKS API that is not limited to one home /32 plus VNet Integration")


def lab_exceptions_current():
    return datetime.datetime.now(datetime.timezone.utc).date() < datetime.date(2026, 12, 8)


def retired_rules(plan):
    """(NSG name, rule name) of standalone rules this plan deletes."""
    retired = set()
    for change in plan.get("resource_changes", []):
        if change.get("type") == "azurerm_network_security_rule" and change["change"]["actions"] == ["delete"]:
            before = change["change"].get("before") or {}
            retired.add((before.get("network_security_group_name"), before.get("name")))
    return retired


def mirrored_rules(resources, address, retired=frozenset()):
    """Standalone rule addresses that an NSG's refreshed inline rules mirror, or None.

    After apply, Azure returns standalone azurerm_network_security_rule objects inside
    their parent NSG, so the plan repeats them in the NSG's security_rule list and
    Checkov flags the NSG too. Re-attribute only when every inline rule is one of the
    plan's standalone rules on that NSG, or a standalone rule this plan deletes (the
    refresh still shows it; the apply removes it). An unknown inline rule keeps the
    finding. Each surviving standalone rule is also scanned on its own.
    """
    if not address.startswith("azurerm_network_security_group."):
        return None
    nsg = resources.get(address) or {}
    standalone = {v.get("name"): a for a, v in resources.items()
                  if a.startswith("azurerm_network_security_rule.")
                  and v.get("network_security_group_name") == nsg.get("name")}
    inline = [rule.get("name") for rule in nsg.get("security_rule") or []]
    leaving = {name for name in inline if (nsg.get("name"), name) in retired and name not in standalone}
    if not inline or any(name not in standalone and name not in leaving for name in inline):
        return None
    return {standalone[name] for name in inline if name in standalone} | {"retired:" + name for name in leaving}


def verify(report, plan, status, allowed):
    if report["check_type"] != "terraform_plan" or status not in (0, 1):
        raise ValueError("Checkov did not complete a Terraform plan scan")
    summary, results = report["summary"], report["results"]
    failures = results["failed_checks"]
    if (summary["parsing_errors"] or results.get("parsing_errors") or summary["skipped"]
            or summary["resource_count"] <= 0 or summary["failed"] != len(failures)
            or summary["passed"] + len(failures) <= 0 or bool(status) != bool(failures)):
        raise ValueError("Incomplete or inconsistent Checkov plan report")

    resources = {r["address"]: r["values"] for r in plan["planned_values"]["root_module"]["resources"]
                 if r["mode"] == "managed"}
    if not resources:
        raise ValueError("No managed resources in the saved plan")
    check_stage(plan)
    check_backup_changes(plan, resources)
    check_outpost_state(resources)
    retired = retired_rules(plan)
    unexpected = set()
    for finding in failures:
        rule = finding["check_id"]
        address = finding.get("resource_address") or finding["resource"]
        basic = address != "azurerm_container_registry.images" or resources.get(address, {}).get("sku") == "Basic"
        mirrors = mirrored_rules(resources, address, retired) or set()
        # A finding explained by a rule this plan deletes describes the pre-apply state.
        approved = ((rule, address) in allowed or any((rule, m) in allowed for m in mirrors)
                    or any(m.startswith("retired:") for m in mirrors))
        if not approved or address not in resources or not basic:
            # Resource indexes and scanner evidence can contain private values.
            unexpected.add(rule if re.fullmatch(r"CKV2?_[A-Z0-9_]+", rule) else "unknown check")
    if unexpected:
        raise ValueError("Unapproved plan finding(s): " + ", ".join(sorted(unexpected)))
    if failures and not lab_exceptions_current():
        raise ValueError("The lab plan exceptions have expired")
    return len(failures)


if __name__ == "__main__":
    try:
        report = json.loads(Path(sys.argv[1]).read_text())
        plan = json.loads(Path(sys.argv[2]).read_text())
        count = verify(report, plan, int(sys.argv[3]), exceptions(Path(__file__).resolve().parents[2]))
    except (OSError, KeyError, IndexError, TypeError, ValueError, AttributeError) as error:
        # Never echo a scanner report, plan, or source value.
        if type(error) is ValueError and not isinstance(error, json.JSONDecodeError):
            print(str(error), file=sys.stderr)
        else:
            print("Invalid Checkov report or saved plan.", file=sys.stderr)
        sys.exit(1)
    print(f"Plan scan passed with {count} reviewed resource-specific findings.")
