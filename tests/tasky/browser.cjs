const assert = require("node:assert/strict");
const { randomBytes } = require("node:crypto");
const { chromium } = require("playwright-core");

async function main() {
  const base = new URL(process.argv[2]);
  assert.equal(base.hostname, "127.0.0.1");
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH, headless: true });
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on("pageerror", () => errors.push("JavaScript error"));
    page.on("console", message => { if (/Content Security Policy/i.test(message.text())) errors.push("CSP violation"); });
    await page.goto(base.href);
    await page.fill("#signupname", "Browser test");
    await page.fill("#signupemail", "browser@example.invalid");
    await page.fill("#signuppass", randomBytes(24).toString("hex"));
    await page.click("#signupbtn");
    await page.waitForURL("**/todo");
    const inertMarkup = '<em data-outpost-probe="yes">sample</em>';
    await page.fill(".task-input input", inertMarkup);
    await page.press(".task-input input", "Enter");
    const content = page.locator(".task-box p").filter({ hasText: inertMarkup });
    await content.waitFor();
    assert.equal(await content.textContent(), inertMarkup);
    assert.equal(await page.locator("[data-outpost-probe]").count(), 0);
    await page.reload();
    await content.waitFor();
    assert.equal(await page.locator("[data-outpost-probe]").count(), 0);
    assert.deepEqual(errors, []);
    console.log("PASS Chromium stored markup renders as literal text after reload under the shipped CSP");
  } finally {
    await browser.close();
  }
}
main().catch(() => { console.error("FAIL Chromium Tasky UI or content-security check"); process.exitCode = 1; });
