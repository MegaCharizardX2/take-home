"""Accept only Checkov plan exceptions for the exact reviewed root resource."""

import datetime
import json
from pathlib import Path
import re
import sys


ENTRY = re.compile(
    r"\s*- '(CKV2?_AZURE_\d+):([\w-]+)\\\.tf\$'\s+# \[(\w+)\.(\w+)\] \S.*"
)


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


def check_backup_changes(plan, resources):
    """Confine public access and policy exemption writes to the approved baseline."""
    for change in plan.get("resource_changes", []):
        operation = change["change"]
        if not {"create", "update"}.intersection(operation["actions"]):
            continue
        value = operation["after"]
        kind = change["type"]
        opens_account = kind == "azurerm_storage_account" and value.get("allow_nested_items_to_be_public") is True
        opens_container = kind == "azurerm_storage_container" and value.get("container_access_type") in ("blob", "container")
        if opens_account or opens_container:
            expected = "azurerm_storage_account.backup" if opens_account else "azurerm_storage_container.backups"
            if change["address"] != expected or plan["variables"]["backup_stage"]["value"] != "public":
                raise ValueError("Refusing public storage outside the approved backup stage and resource")
        is_arm_exemption = (kind.startswith("azapi_") and
                            str(value.get("type", "")).split("@")[0].lower() == "microsoft.authorization/policyexemptions")
        if not kind.endswith("_policy_exemption") and not is_arm_exemption:
            continue
        account = resources.get("azurerm_storage_account.backup", {}).get("id", "")
        match = re.fullmatch(
            r"(/subscriptions/[0-9a-f-]{36})/resourcegroups/takehome-rg/providers/"
            r"microsoft\.storage/storageaccounts/stoutpost[0-9a-f]{10}", account.lower()
        )
        assignment = "/providers/microsoft.authorization/policyassignments/securitycenterbuiltin"
        try:
            expires = datetime.datetime.fromisoformat(str(value.get("expires_on", "")).replace("Z", "+00:00"))
        except ValueError:
            expires = None
        if (not match or kind != "azurerm_resource_policy_exemption"
                or change["address"] != "azurerm_resource_policy_exemption.backup[0]"
                or value.get("name") != "wiz-public-backup-baseline"
                or value.get("resource_id", "").lower() != account.lower()
                or value.get("policy_assignment_id", "").lower() != match[1] + assignment
                or value.get("policy_definition_reference_ids") != ["StorageDisallowPublicAccess"]
                or value.get("exemption_category") != "Waiver"
                or expires != datetime.datetime(2026, 12, 8, tzinfo=datetime.timezone.utc)):
            raise ValueError("Refusing a policy exemption outside the approved backup waiver")


def lab_exceptions_current():
    return datetime.datetime.now(datetime.timezone.utc).date() < datetime.date(2026, 12, 8)


def mirrored_rules(resources, address):
    """Standalone rule addresses that an NSG's refreshed inline rules mirror, or None.

    After apply, Azure returns standalone azurerm_network_security_rule objects inside
    their parent NSG, so the plan repeats them in the NSG's security_rule list and
    Checkov flags the NSG too. Re-attribute only when every inline rule is one of the
    plan's standalone rules on that NSG; an unknown inline rule keeps the finding.
    """
    if not address.startswith("azurerm_network_security_group."):
        return None
    nsg = resources.get(address) or {}
    standalone = {v.get("name"): a for a, v in resources.items()
                  if a.startswith("azurerm_network_security_rule.")
                  and v.get("network_security_group_name") == nsg.get("name")}
    inline = [rule.get("name") for rule in nsg.get("security_rule") or []]
    if not inline or any(name not in standalone for name in inline):
        return None
    return {standalone[name] for name in inline}


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
    check_backup_changes(plan, resources)
    unexpected = set()
    for finding in failures:
        rule = finding["check_id"]
        address = finding.get("resource_address") or finding["resource"]
        basic = address != "azurerm_container_registry.images" or resources.get(address, {}).get("sku") == "Basic"
        mirrors = mirrored_rules(resources, address) or set()
        approved = (rule, address) in allowed or any((rule, m) in allowed for m in mirrors)
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
