const test = require("node:test");
const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const timers = require("node:timers/promises");
const { open, close } = require("./open.cjs");
const { cleanup } = require("./close.cjs");
const os = require("node:os");
const path = require("node:path");

const sub = "00000000-0000-0000-0000-000000000001";
const name = "kv-outpost-0123456789";
const ip = "8.8.8.8";

function runner(t, losePatchResponse = false) {
  process.env.ARM_SUBSCRIPTION_ID = sub;
  process.env.INPUT_VAULT = name;
  const properties = {
    publicNetworkAccess: "Disabled", enableRbacAuthorization: true, enablePurgeProtection: true,
    networkAcls: { defaultAction: "Deny", bypass: "AzureServices", ipRules: [], virtualNetworkRules: [] },
  };
  let state = "";
  t.mock.method(fs, "appendFileSync", (_, data) => { state += data; });
  t.mock.method(timers, "setTimeout", async () => {});
  const exec = childProcess.execFileSync;
  t.mock.method(childProcess, "execFileSync", (program, args, options) => {
    if (program === "curl") return ip;
    if (program === "python3") return exec(program, args, options);
    assert.equal(program, "az");
    if (args[0] === "rest" && args[2] === "get") {
      return JSON.stringify({ tags: { owner: "takehome" }, properties });
    }
    if (args[0] === "rest" && args[2] === "patch") {
      const change = JSON.parse(args[args.indexOf("--body") + 1]).properties;
      assert.match(state, /ip=8\.8\.8\.8\n/);
      Object.assign(properties, change);
      if (losePatchResponse) throw Error("Lost response after ARM accepted the write");
    } else if (args.slice(0, 3).join(" ") === "keyvault key list") {
      assert.equal(properties.networkAcls.defaultAction, "Deny");
      assert.deepEqual(properties.networkAcls.ipRules, [{ value: ip + "/32" }]);
    } else if (args.slice(0, 2).join(" ") === "keyvault update") {
      assert.equal(args[args.indexOf("--public-network-access") + 1], "Disabled");
      properties.publicNetworkAccess = "Disabled";
    } else if (args.slice(0, 3).join(" ") === "keyvault network-rule remove") {
      assert.equal(properties.publicNetworkAccess, "Disabled");
      const value = args[args.indexOf("--ip-address") + 1];
      properties.networkAcls.ipRules = properties.networkAcls.ipRules.filter(rule => rule.value !== value);
    } else {
      throw Error("Unexpected Azure CLI call");
    }
    return "";
  });
  return properties;
}

test("job cleanup disables public access, removes only the runner and can be repeated", async t => {
  const p = runner(t);
  await open();
  assert.equal(p.publicNetworkAccess, "Enabled");
  p.networkAcls.ipRules.push({ value: "1.1.1.1/32" });
  await close(sub, name, ip);
  await close(sub, name, ip);
  assert.equal(p.publicNetworkAccess, "Disabled");
  assert.deepEqual(p.networkAcls.ipRules, [{ value: "1.1.1.1/32" }]);
});

test("a lost response after opening the firewall closes the vault immediately", async t => {
  const p = runner(t, true);
  await assert.rejects(open(), /Lost response/);
  assert.equal(p.publicNetworkAccess, "Disabled");
  assert.deepEqual(p.networkAcls.ipRules, []);
});

test("a pre-existing IP rule prevents opening the public endpoint", async t => {
  const p = runner(t);
  p.networkAcls.ipRules.push({ value: "1.1.1.1/32" });
  await assert.rejects(open(), /closed baseline/);
  assert.equal(p.publicNetworkAccess, "Disabled");
});

test("the explicit cleanup and post-action share one private lease", async t => {
  const p = runner(t);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-lease-"));
  const lease = path.join(dir, "lease.json");
  const previous = process.env.VAULT_ACCESS_LEASE_FILE;
  process.env.VAULT_ACCESS_LEASE_FILE = lease;
  t.after(() => {
    if (previous === undefined) delete process.env.VAULT_ACCESS_LEASE_FILE;
    else process.env.VAULT_ACCESS_LEASE_FILE = previous;
    fs.rmSync(dir, { recursive: true, force: true });
  });
  await open();
  assert.equal(fs.statSync(lease).mode & 0o777, 0o600);
  await cleanup();
  assert.equal(p.publicNetworkAccess, "Disabled");
  assert.deepEqual(p.networkAcls.ipRules, []);
  assert.equal(fs.existsSync(lease), false);
  await cleanup();
});
