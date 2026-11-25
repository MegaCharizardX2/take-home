const childProcess = require("node:child_process");
const fs = require("node:fs");
const timers = require("node:timers/promises");

function az(...args) {
  return childProcess.execFileSync("az", [...args, "--only-show-errors"], {
    encoding: "utf8",
    timeout: 30_000,
  });
}

function vaultUrl(subscription, vault) {
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(subscription) ||
      !/^kv-outpost-[0-9a-f]{10}$/.test(vault)) {
    throw new Error("Expected the protected subscription ID and lab vault name.");
  }
  return "https://management.azure.com/subscriptions/" + subscription +
    "/resourceGroups/takehome-rg/providers/Microsoft.KeyVault/vaults/" + vault + "?api-version=2024-11-01";
}

function read(url) {
  return JSON.parse(az("rest", "--method", "get", "--url", url, "-o", "json"));
}

function patch(url, properties) {
  az("rest", "--method", "patch", "--url", url, "--body", JSON.stringify({ properties }), "-o", "none");
}

async function waitFor(description, check) {
  const deadline = Date.now() + 180_000;
  let lastError;
  do {
    try {
      if (check()) return;
    } catch (error) {
      lastError = error;
    }
    await timers.setTimeout(5_000);
  } while (Date.now() < deadline);
  throw new Error("Timed out " + description, { cause: lastError });
}

function matchesIp(rule, ip) {
  return rule.value === ip || rule.value === ip + "/32";
}

async function close(subscription, vault, ip) {
  const url = vaultUrl(subscription, vault);
  // Disable the endpoint first. Preserve any unrelated rules for operator review.
  // The opening PATCH may have reached ARM even if the runner lost its response.
  await waitFor("disabling public access", () => {
    az("keyvault", "update", "--subscription", subscription, "--resource-group", "takehome-rg",
      "--name", vault, "--public-network-access", "Disabled", "-o", "none");
    return true;
  });
  await waitFor("closing the vault firewall", () => {
    const properties = read(url).properties;
    if (properties.publicNetworkAccess !== "Disabled") {
      patch(url, { publicNetworkAccess: "Disabled" });
      return false;
    }
    const ours = properties.networkAcls?.ipRules?.find(rule => matchesIp(rule, ip));
    if (!ours) return true;
    az("keyvault", "network-rule", "remove", "--subscription", subscription,
      "--resource-group", "takehome-rg", "--name", vault, "--ip-address", ours.value, "-o", "none");
    return false;
  });
}

async function open() {
  const subscription = process.env.ARM_SUBSCRIPTION_ID;
  const vault = process.env.INPUT_VAULT;
  const url = vaultUrl(subscription, vault);
  const resource = read(url);
  const p = resource.properties;
  const acl = p.networkAcls;
  if (resource.tags?.owner !== "takehome" || !p.enableRbacAuthorization || !p.enablePurgeProtection ||
      p.publicNetworkAccess !== "Disabled" || acl?.defaultAction !== "Deny" || acl.bypass !== "AzureServices" ||
      acl.ipRules?.length || acl.virtualNetworkRules?.length) {
    throw new Error("Vault is outside the expected closed baseline. Check its firewall before retrying.");
  }

  const observed = childProcess.execFileSync("curl", ["-4fsS", "--max-time", "10", "--retry", "2",
    "https://checkip.amazonaws.com"], { encoding: "utf8" }).trim();
  const checkIp = [
    "import ipaddress, sys",
    "ip = ipaddress.IPv4Address(sys.argv[1])",
    "if not ip.is_global or ip.is_multicast:",
    "    sys.exit('Expected a public runner IPv4')",
    "print(ip)",
  ].join("\n");
  const ip = childProcess.execFileSync("python3", ["-I", "-c", checkIp, observed], { encoding: "utf8" }).trim();

  // Register cleanup before ARM can accept the first write.
  fs.appendFileSync(process.env.GITHUB_STATE, "subscription=" + subscription + "\nvault=" + vault + "\nip=" + ip + "\n");
  try {
    patch(url, {
      publicNetworkAccess: "Enabled",
      networkAcls: { defaultAction: "Deny", bypass: "AzureServices", ipRules: [{ value: ip + "/32" }], virtualNetworkRules: [] },
    });
    await waitFor("verifying runner access to the vault", () => {
      const current = read(url).properties;
      const rules = current.networkAcls;
      if (current.publicNetworkAccess !== "Enabled" || rules?.defaultAction !== "Deny" ||
          rules.bypass !== "AzureServices" || rules.virtualNetworkRules?.length ||
          rules.ipRules?.length !== 1 || !matchesIp(rules.ipRules[0], ip)) return false;
      az("keyvault", "key", "list", "--subscription", subscription, "--vault-name", vault, "-o", "none");
      return true;
    });
  } catch (error) {
    await close(subscription, vault, ip);
    throw error;
  }
}

module.exports = { open, close };
if (require.main === module) {
  open().catch(error => { console.error(error.message); process.exitCode = 1; });
}
