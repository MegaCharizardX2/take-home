const { close } = require("./open.cjs");
const fs = require("node:fs");

async function cleanup() {
  const leasePath = process.env.VAULT_ACCESS_LEASE_FILE;
  if (leasePath) {
    // The explicit always() step and the GitHub post-action share this lease.
    if (!fs.existsSync(leasePath)) return;
    const { subscription, vault, ip } = JSON.parse(fs.readFileSync(leasePath, "utf8"));
    await close(subscription, vault, ip);
    fs.unlinkSync(leasePath);
  } else if (process.env.STATE_ip) {
    await close(process.env.STATE_subscription, process.env.STATE_vault, process.env.STATE_ip);
  }
}
module.exports = { cleanup };
if (require.main === module) {
  cleanup().catch(error => { console.error(error.message); process.exitCode = 1; });
}
