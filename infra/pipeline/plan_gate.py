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
DELETES = {
    "azurerm_public_ip.mongo", "azurerm_network_security_rule.ssh",
    "azurerm_resource_policy_exemption.backup[0]",
    'azurerm_role_assignment.lab["vm_compute"]', 'azurerm_role_assignment.lab["vm_backup"]',
}

AKS = "azapi_resource.aks"
ACCOUNT = "azurerm_storage_account.backup"
CONTAINER = "azurerm_storage_container.backups"
NAT = "azurerm_public_ip.nat"
IDENTITY = "data.azurerm_user_assigned_identity.lab"
# Each grant is checked against the actual IDs from refreshed resources in the same plan.
ROLES = {
    'aks_network["nodes"]': ("id-aks-control-plane", "Network Contributor", 'azurerm_subnet.lab["nodes"]'),
    'aks_network["api"]': ("id-aks-control-plane", "Network Contributor", 'azurerm_subnet.lab["api"]'),
    'aks_network["ingress"]': ("id-aks-control-plane", "Network Contributor", "azurerm_public_ip.ingress"),
    "kubelet_operator": ("id-aks-control-plane", "Managed Identity Operator", f'{IDENTITY}["id-aks-kubelet"]'),
    'lab["vm_writer"]': ("id-mongo", "Lab Backup Writer", CONTAINER),
    'lab["reader"]': ("id-backup-reader", "Storage Blob Data Reader", CONTAINER),
    'lab["infra_admin"]': ("takehome-id", "Azure Kubernetes Service RBAC Cluster Admin", AKS),
    'lab["release_write"]': ("id-release", "Azure Kubernetes Service RBAC Writer", AKS),
    'lab["release_run"]': ("id-release", "Lab AKS Run Command", AKS),
    'lab["release_nodes"]': ("id-release", "Lab AKS Node Reader", AKS),
    'lab["schedule_aks"]': ("id-lab-scheduler", "Lab Power Operator", AKS),
    'lab["schedule_vm"]': ("id-lab-scheduler", "Lab Power Operator", "azurerm_linux_virtual_machine.mongo"),
    "registry_pull": ("id-aks-kubelet", "Container Registry Repository Reader", "azurerm_container_registry.images"),
    "registry_push": ("id-image-publisher", "Container Registry Repository Writer", "azurerm_container_registry.images"),
    "crypto_officer": ("takehome-id", "Key Vault Crypto Officer", "azurerm_key_vault.lab"),
    "mongo_disk_key": ("id-disk-cmk", "Key Vault Crypto Service Encryption User", "azurerm_key_vault_key.mongo_disk"),
    "backup_cmk": ("id-backup-cmk", "Key Vault Crypto Service Encryption User", "azurerm_key_vault_key.backup"),
}
# Traefik's frontend and the NAT gateway's egress address are the only public IPs.
PUBLIC_IPS = {"azurerm_public_ip.ingress", "azurerm_public_ip.nat"}


class GateError(ValueError):
    """A diagnostic that is safe to write to the public workflow log."""


def exceptions(root):
    pairs = set()
    for line in (root / "policy" / ".checkov.yaml").read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#") or line.strip() == "skip-check:":
            continue
        match = ENTRY.fullmatch(line)
        if not match:
            raise GateError("Invalid file-scoped exception or missing resource address")
        rule, filename, kind, name = match.groups()
        source = (root / "infra" / (filename + ".tf")).read_text()
        declaration = rf'^resource\s+"{kind}"\s+"{name}"\s*\{{'
        if not re.search(declaration, source, re.MULTILINE):
            raise GateError("Exception resource is absent from its approved file")
        pairs.add((rule, f"{kind}.{name}"))
    return pairs


def check_stage(plan):
    """Outpost is one-way: replaying a Phase-1 stage would reopen the weaknesses."""
    if plan.get("variables", {}).get("backup_stage", {}).get("value") != STAGE:
        raise GateError("Refusing a Phase-1 stage: only the outpost stage can be planned")


def check_actions(changes):
    accepted = True
    for change in changes:
        address = change["address"]
        actions = change["change"]["actions"]
        # An index can contain quotes or control characters. Keep it on a single log line.
        display = json.dumps(address, ensure_ascii=True)[1:-1].replace(r'\"', '"')
        known = {"no-op", "read", "create", "update", "delete", "forget"}
        print(f"{display} {'/'.join(actions) if all(a in known for a in actions) else 'unknown action'}")
        if actions not in (["no-op"], ["read"], ["create"], ["update"]):
            accepted &= actions == ["delete"] and address in DELETES
    if not accepted:
        raise GateError("Refusing a replacement, unapproved deletion or unsupported action")


def check_role(address, value, resources):
    name = address.removeprefix("azurerm_role_assignment.")
    if name not in ROLES:
        raise GateError("Refusing an unreviewed role assignment")
    identity, role, target = ROLES[name]
    actor = resources.get(f'{IDENTITY}["{identity}"]', {})
    principal = actor.get("principal_id")
    field = "resource_versionless_id" if target.startswith("azurerm_key_vault_key.") else "id"
    scope = resources.get(target, {}).get(field)
    if scope and name == 'lab["release_write"]':
        scope += "/namespaces/wiz-web"
    if (actor.get("name") != identity or not principal or not scope or value.get("role_definition_name") != role
            or str(value.get("principal_id")).lower() != principal.lower()
            or str(value.get("scope")).lower() != scope.lower()):
        raise GateError("Refusing a role assignment with an unknown or unapproved principal, role or scope")


def check_storage_step(plan, resources):
    step = plan["variables"].get("storage_step", {}).get("value")
    if step not in ("A", "B"):
        raise GateError("Refusing an unknown storage step")
    change = next((r["change"] for r in plan.get("resource_changes", []) if r["address"] == ACCOUNT), {})
    before = change.get("before") or {}
    if step == "B" and before.get("public_network_access_enabled") is True and not before.get("customer_managed_key"):
        raise GateError("Refusing to skip the private-storage transition in step A")
    if step == "A":
        if (ACCOUNT not in resources or change.get("actions") != ["update"]
                or before.get("public_network_access_enabled") is not True or before.get("customer_managed_key")
                or change.get("after_unknown", {}).get("customer_managed_key")
                or resources[ACCOUNT].get("customer_managed_key") not in (None, [])):
            raise GateError("Refusing step A outside the initial transition from public storage without a CMK")
    return step


def check_backup_changes(plan):
    """Refuse public storage and any policy exemption write in every plan."""
    for change in plan.get("resource_changes", []):
        operation = change["change"]
        if change["type"].startswith("azapi_") and change["address"] != AKS:
            raise GateError("Refusing an unreviewed AzAPI resource or exemption")
        if not {"create", "update"}.intersection(operation["actions"]):
            continue
        value = operation["after"] or {}
        kind = change["type"]
        opens_account = kind == "azurerm_storage_account" and (
            value.get("allow_nested_items_to_be_public") is not False or value.get("public_network_access_enabled") is not False)
        opens_container = kind == "azurerm_storage_container" and value.get("container_access_type") != "private"
        if opens_account or opens_container:
            raise GateError("Refusing public storage in the outpost stage")
        if kind.endswith("_policy_exemption"):
            raise GateError("Refusing a policy exemption in the outpost stage")


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
    return (network.version == 4 and network.prefixlen == 32 and network.network_address.is_global
            and not network.network_address.is_multicast)


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


def check_outpost_state(plan, resources, kinds, step):
    """Each remediated resource that is in the plan must stay remediated.

    The checks are presence-conditional so targeted bootstrap plans still pass.
    Failures name the control only: plan values can contain private data.
    """
    for address, value in resources.items():
        kind = kinds[address]
        if kind.endswith("_policy_exemption"):
            raise GateError("Refusing a plan that keeps a policy exemption")
        if kind == "azurerm_public_ip" and address not in PUBLIC_IPS:
            raise GateError("Refusing a public IP outside ingress and NAT egress")
        if kind == "azurerm_network_interface" and any(
                (config or {}).get("public_ip_address_id") for config in value.get("ip_configuration") or []):
            raise GateError("Refusing a public IP on a network interface")
        # Standalone rules only: an NSG's inline list is a refreshed mirror that still
        # shows rules this plan deletes. Unknown inline rules fail in mirrored_rules.
        if kind == "azurerm_network_security_rule" and _opens_ssh(value):
            raise GateError("Refusing an inbound SSH allow rule")
        if kind == "azurerm_role_assignment":
            check_role(address, value, resources)
        if kind.startswith("azapi_") and address != AKS:
            raise GateError("Refusing an unreviewed AzAPI resource")
    account = resources.get(ACCOUNT)
    if account is not None:
        identity = (account.get("identity") or [{}])[0] or {}
        if (account.get("public_network_access_enabled") is not False
                or account.get("allow_nested_items_to_be_public") is not False
                or account.get("shared_access_key_enabled") is not False
                or identity.get("type") != "UserAssigned"):
            raise GateError("Refusing a backup account without private access and a user-assigned identity")
        if step == "B":
            key = (account.get("customer_managed_key") or [{}])[0] or {}
            expected_key = resources.get("azurerm_key_vault_key.backup", {}).get("versionless_id")
            cmk_identity = resources.get(f'{IDENTITY}["id-backup-cmk"]', {})
            expected_id = cmk_identity.get("id")
            if (not expected_key or key.get("key_vault_key_id") != expected_key
                    or cmk_identity.get("name") != "id-backup-cmk" or not expected_id
                    or str(key.get("user_assigned_identity_id")).lower() != expected_id.lower()
                    or expected_id.lower() not in [item.lower() for item in identity.get("identity_ids") or []]):
                raise GateError("Refusing a backup account without its CMK in step B")
        if 'azurerm_private_endpoint.lab["blob"]' not in resources:
            raise GateError("Refusing a backup account without its Blob private endpoint")
    container = resources.get(CONTAINER)
    if container is not None and container.get("container_access_type") != "private":
        raise GateError("Refusing a public backup container")
    aks = resources.get(AKS)
    if aks is not None:
        if str(aks.get("type", "")).split("@")[0].lower() != "microsoft.containerservice/managedclusters":
            raise GateError("Refusing an AzAPI type other than the reviewed AKS cluster")
        home = plan["variables"]["aks_api_home_cidr"]["value"]
        allow_nat = plan["variables"]["allow_nat_api"]["value"]
        if not _public_slash32(home) or type(allow_nat) is not bool:
            raise GateError("Refusing an invalid AKS allowlist configuration")
        expected = [home]
        if allow_nat:
            nat = next((r["change"] for r in plan["resource_changes"] if r["address"] == NAT), {})
            live = (nat.get("before") or {}).get("ip_address")
            cidr = f"{live}/32"
            if (not _public_slash32(cidr) or cidr == home
                    or (nat.get("before") or {}).get("name") != "pip-nat"
                    or resources.get(NAT, {}).get("ip_address") != live):
                raise GateError("Refusing an AKS NAT allowance without a stable live NAT address")
            expected.append(cidr)
        profile = _body(aks).get("properties", {}).get("apiServerAccessProfile", {})
        ranges = profile.get("authorizedIPRanges")
        if (profile.get("enableVnetIntegration") is not True or profile.get("enablePrivateCluster") is True
                or not isinstance(ranges, list) or sorted(ranges) != sorted(expected)):
            raise GateError("Refusing an AKS API that is not limited to its reviewed /32 ranges plus VNet Integration")


def lab_exceptions_current():
    return datetime.datetime.now(datetime.timezone.utc).date() < datetime.date.fromisoformat(
        (Path(__file__).resolve().parents[1] / "lab-expiry.txt").read_text().strip())


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
        raise GateError("Checkov did not complete a Terraform plan scan")
    summary, results = report["summary"], report["results"]
    failures = results["failed_checks"]
    if (summary["parsing_errors"] or results.get("parsing_errors") or summary["skipped"]
            or summary["resource_count"] <= 0 or summary["failed"] != len(failures)
            or summary["passed"] + len(failures) <= 0 or bool(status) != bool(failures)):
        raise GateError("Incomplete or inconsistent Checkov plan report")

    module = plan["planned_values"]["root_module"]
    pending = [module]
    resources, kinds = {}, {}
    managed = False
    while pending:
        current = pending.pop()
        pending.extend(current.get("child_modules", []))
        for r in current.get("resources", []):
            address = r["address"]
            resources[address] = r["values"]
            kinds[address] = r["type"]
            managed |= r["mode"] == "managed"
    if not managed:
        raise GateError("No managed resources in the saved plan")
    check_actions(plan.get("resource_changes", []))
    check_stage(plan)
    step = check_storage_step(plan, resources)
    check_backup_changes(plan)
    check_outpost_state(plan, resources, kinds, step)
    retired = retired_rules(plan)
    unexpected = set()
    for finding in failures:
        rule = finding["check_id"]
        address = finding.get("resource_address") or finding["resource"]
        basic = address != "azurerm_container_registry.images" or resources.get(address, {}).get("sku") == "Basic"
        mirrors = mirrored_rules(resources, address, retired) or set()
        # A finding explained by a rule this plan deletes describes the pre-apply state.
        # Step A closes public storage immediately so a later step B CMK failure leaves the backups private.
        initial_cmk_transition = step == "A" and rule == "CKV2_AZURE_1" and address == ACCOUNT
        approved = (initial_cmk_transition or (rule, address) in allowed or any((rule, m) in allowed for m in mirrors)
                    or (rule == "CKV_AZURE_10" and any(m.startswith("retired:") for m in mirrors)))
        if not approved or address not in resources or not basic:
            # Resource indexes and scanner evidence can contain private values.
            unexpected.add(rule if re.fullmatch(r"CKV2?_[A-Z0-9_]+", rule) else "unknown check")
    if unexpected:
        raise GateError("Unapproved plan finding(s): " + ", ".join(sorted(unexpected)))
    if failures and not lab_exceptions_current():
        raise GateError("The lab plan exceptions have expired")
    return len(failures)


if __name__ == "__main__":
    try:
        report = json.loads(Path(sys.argv[1]).read_text())
        plan = json.loads(Path(sys.argv[2]).read_text())
        count = verify(report, plan, int(sys.argv[3]), exceptions(Path(__file__).resolve().parents[2]))
    except (OSError, KeyError, IndexError, TypeError, ValueError, AttributeError) as error:
        # Never echo a scanner report, plan, or source value.
        if isinstance(error, GateError):
            print(str(error), file=sys.stderr)
        else:
            print("Invalid Checkov report or saved plan.", file=sys.stderr)
        sys.exit(1)
    print(f"Plan scan passed with {count} reviewed resource-specific findings.")
