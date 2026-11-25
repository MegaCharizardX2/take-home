const { close } = require("./open.cjs");

// An early preflight failure makes no change and records no IP.
if (process.env.STATE_ip) {
  close(process.env.STATE_subscription, process.env.STATE_vault, process.env.STATE_ip)
    .catch(error => { console.error(error.message); process.exitCode = 1; });
}
