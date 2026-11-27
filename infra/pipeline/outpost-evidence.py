"""Read-only evidence from the authenticated infra identity and the external runner."""
import functools
import ipaddress
import json
import os
import re
import subprocess
import sys
from fnmatch import fnmatchcase
from urllib.parse import urlsplit
from uuid import UUID

ARM = "https://management.azure.com"
AUTH = "/providers/Microsoft.Authorization/"
STORAGE = "2025-08-01"
NETWORK = "2024-07-01"
RBAC = "2022-04-01"
BLOBS = "microsoft.storage/storageaccounts/blobservices/containers/blobs/"
READER = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"


def require(condition):
    if not condition:
        raise ValueError("check failed")


@functools.lru_cache(None)
def get(url):
    require(urlsplit(url).netloc == "management.azure.com" and url.startswith(ARM + "/"))
    reply = subprocess.run(["az", "rest", "--method", "get", "--url", url, "--only-show-errors", "-o", "json"],
                           check=True, capture_output=True, timeout=90)
    return json.loads(reply.stdout)


def url(path, version):
    return ARM + path + "?api-version=" + version


def items(path, version, query=""):
    page = url(path, version) + query
    seen = set()
    while page:
        require(page not in seen)
        seen.add(page)
        body = get(page)
        require(isinstance(body["value"], list))
        yield from body["value"]
        page = body.get("nextLink")


def prop(path, version):
    return get(url(path, version))["properties"]


@functools.lru_cache(None)
def account():
    path = rg + "/providers/Microsoft.Storage/storageAccounts"
    name, = [r["name"] for r in items(path, STORAGE) if re.fullmatch(r"stoutpost[0-9a-f]{10}", r["name"])]
    return path + "/" + name


def container():
    return account() + "/blobServices/default/containers/backups"


def storage():
    p = prop(account(), STORAGE)
    e = p["encryption"]
    require(p["publicNetworkAccess"] == "Disabled" and p["allowBlobPublicAccess"] is False
            and p["allowSharedKeyAccess"] is False and p["networkAcls"]["defaultAction"] == "Deny"
            and e["keySource"].lower() == "microsoft.keyvault"
            and e["keyvaultproperties"]["keyname"].lower() == "backup-cmk"
            and e["keyvaultproperties"]["keyvaulturi"].lower().rstrip("/") ==
            "https://kv-outpost-" + account()[-10:] + ".vault.azure.net"
            and e["identity"]["userAssignedIdentity"].lower() == identity("id-backup-cmk").lower())


def private_endpoint():
    require(prop(container(), STORAGE).get("publicAccess", "None") == "None")
    require(any(x["properties"]["privateLinkServiceConnectionState"]["status"] == "Approved"
                for x in items(account() + "/privateEndpointConnections", STORAGE)))


def exemption():
    require(all(x["name"].lower() != "wiz-public-backup-baseline"
                for x in items(account() + AUTH + "policyExemptions", "2022-07-01-preview")))


def curl(endpoint, fields):
    return subprocess.run(["curl", "-q", "--noproxy", "*", "--silent", "--connect-timeout", "8",
                           "--max-time", "15", "--output", os.devnull, "--write-out", fields, endpoint],
                          capture_output=True, timeout=20, text=True)


def anonymous():
    name = account().rsplit("/", 1)[1]
    reply = curl(f"https://{name}.blob.core.windows.net/backups?restype=container&comp=list", "%{http_code}")
    require(reply.returncode == 0 and reply.stdout in {"403", "409"})
    return f" (HTTP {reply.stdout})"


def no_public_ip():
    nic = prop(rg + "/providers/Microsoft.Network/networkInterfaces/nic-mongo", NETWORK)
    require(nic["ipConfigurations"] and all(not p["properties"].get("publicIPAddress") for p in nic["ipConfigurations"]))
    require(all(p["name"].lower() != "pip-mongo" for p in items(rg + "/providers/Microsoft.Network/publicIPAddresses", NETWORK)))


def ssh():
    nsg = prop(rg + "/providers/Microsoft.Network/networkSecurityGroups/nsg-mongo", NETWORK)
    denied = False
    for entry in nsg["securityRules"]:
        rule = entry["properties"]
        if rule["direction"] != "Inbound":
            continue
        for port in [rule.get("destinationPortRange")] + (rule.get("destinationPortRanges") or []):
            if not port:
                continue
            if port != "*":
                limits = [int(n) for n in port.split("-")]
                if not limits[0] <= 22 <= limits[-1]:
                    continue
            require(rule["access"] != "Allow")
            denied |= rule["access"] == "Deny" and rule["sourceAddressPrefix"] == "*" and rule["protocol"].lower() in {"*", "tcp"}
    require(denied)


def identity(name):
    return rg + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/" + name


def blob_roles():
    target = container().lower()
    writer, reader = (str(UUID(prop(identity(n), "2023-01-31")["principalId"])) for n in ("id-mongo", "id-backup-reader"))
    require(writer != reader)
    found = []
    for assignment in items(container() + AUTH + "roleAssignments", RBAC, "&%24filter=atScope()"):
        a = assignment["properties"]
        role = a["roleDefinitionId"]
        require(re.fullmatch(r"/(?:subscriptions/[0-9a-f-]{36}/|providers/Microsoft[.]Management/managementGroups/[a-z0-9_.()-]+/)?"
                             r"providers/Microsoft[.]Authorization/roleDefinitions/[0-9a-f-]{36}",
                             role, flags=re.I))
        definition = prop(role, RBAC)
        perms = definition["permissions"]
        require(isinstance(perms, list) and perms)
        for p in perms:
            require(isinstance(p["dataActions"], list))
        data = [v.lower() for p in perms for v in p["dataActions"]]
        # A wildcard that could select any blob operation is conservatively treated as blob access.
        if not any(BLOBS.startswith(v.split("*")[0]) or v.startswith(BLOBS) for v in data):
            continue
        require(a["scope"].lower() == target)
        principal = str(UUID(a["principalId"]))
        if principal == writer and definition["roleName"] == "Lab Backup Writer":
            require(len(perms) == 1 and all(perms[0][key] == [] for key in ("actions", "notActions", "notDataActions"))
                    and set(data) == {BLOBS + "write", BLOBS + "add/action"})
        else:
            require(principal == reader and role.rsplit("/", 1)[1].lower() == READER)
        found.append(principal)
    require(sorted(found) == sorted([writer, reader]))
    # Also catch the retired VM Contributor grant on the sibling VM or resource group.
    grants = list(items(rg + AUTH + "roleAssignments", RBAC, f"&%24filter=principalId%20eq%20%27{writer}%27"))
    require(len(grants) == 1 and grants[0]["properties"]["scope"].lower() == target
            and str(UUID(grants[0]["properties"]["principalId"])) == writer)
    # Include transitive group grants at and above the VM itself.
    vm = rg + "/providers/Microsoft.Compute/virtualMachines/vm-mongo"
    require(not list(items(vm + AUTH + "roleAssignments", RBAC,
                           f"&%24filter=atScope()%20and%20assignedTo(%27{writer}%27)")))


def aks():
    return prop(rg + "/providers/Microsoft.ContainerService/managedClusters/aks-outpost", "2025-10-01")


def api_ranges():
    profile = aks()["apiServerAccessProfile"]
    home = ipaddress.IPv4Interface(os.environ["AKS_API_HOME_CIDR"])
    require(home.ip.is_global and not home.ip.is_multicast and home.network.prefixlen == 32)
    expected = [str(home)]
    allow_nat = os.environ.get("AKS_API_ALLOW_NAT", "false")
    require(allow_nat in {"true", "false"})
    if allow_nat == "true":
        ip = ipaddress.IPv4Address(prop(rg + "/providers/Microsoft.Network/publicIPAddresses/pip-nat", NETWORK)["ipAddress"])
        require(ip.is_global and not ip.is_multicast and ip != home.ip)
        expected.append(str(ip) + "/32")
    require(profile["enableVnetIntegration"] is True and profile.get("enablePrivateCluster", False) is False
            and sorted(profile["authorizedIPRanges"]) == sorted(expected))


def api_unreachable():
    host = aks()["fqdn"]
    require(re.fullmatch(r"(?:[a-z0-9-]+\.)+azmk8s\.io", host, re.I))
    # DNS must finish and TCP must never connect. TLS errors and HTTP denials prove reachability.
    reply = curl(f"https://{host}/readyz", "%{time_namelookup} %{time_connect} %{http_code}")
    dns, tcp, status = reply.stdout.split()
    require(reply.returncode in {7, 28} and float(dns) > 0 and float(tcp) == 0 and status == "000")


def no_exemption_write():
    # This endpoint evaluates the calling principal, including grants inherited through groups.
    action = "microsoft.authorization/policyexemptions/write"
    permissions = list(items(account() + AUTH + "permissions", "2022-05-01-preview"))
    require(permissions)
    for p in permissions:
        matches = lambda patterns: any(fnmatchcase(action, v.lower()) for v in patterns)
        require(not matches(p["actions"]) or matches(p["notActions"]))


CHECKS = [
    ("backup account private with backup-cmk and Shared Key disabled", storage),
    ("private container with approved private endpoint", private_endpoint),
    ("baseline policy exemption removed", exemption),
    ("external anonymous list refused", anonymous),
    ("database VM has no public IP", no_public_ip),
    ("database NSG denies inbound SSH", ssh),
    ("only the container-scoped backup writer and reader hold blob data roles", blob_roles),
    ("AKS API matches authorized ranges and VNet Integration", api_ranges),
    ("external runner cannot connect to the resolved AKS API name", api_unreachable),
    ("takehome-id cannot write policy exemptions on the backup account", no_exemption_write),
]


def main(mode):
    require(mode in {"evidence", "report"})
    first_failure = 0
    rows = []
    for code, (label, check) in enumerate(CHECKS, 11):
        try:
            detail = check() or ""
        except (ValueError, TypeError, KeyError, AttributeError, OSError, subprocess.SubprocessError):
            rows.append(("FAIL", label))
            print("FAIL", label, file=sys.stderr)
            first_failure = first_failure or code
            if mode != "report":
                break
        else:
            rows.append(("PASS", label + detail))
            print("PASS", label + detail)
    if mode == "report":
        table = ["| Control | Result |", "|---|---|"] + [f"| {label} | {result} |" for result, label in rows]
        print("\n".join(table))
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
                print("\n".join(table), file=summary)
    return first_failure


if __name__ == "__main__":
    try:
        rg = "/subscriptions/" + str(UUID(os.environ["ARM_SUBSCRIPTION_ID"])) + "/resourceGroups/takehome-rg"
        sys.exit(main(sys.argv[1] if len(sys.argv) == 2 else "evidence" if len(sys.argv) == 1 else ""))
    except (KeyError, ValueError):
        sys.exit("Invalid evidence configuration.")
