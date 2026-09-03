/**
 * Print every console message a route produces, in full and untruncated.
 *
 * The render probe abbreviates messages so its problem list stays readable.
 * When a message matters -- a hydration diff, say -- the abbreviation hides the
 * part that identifies the cause, so this prints the whole thing.
 *
 *   node scripts/console-probe.mjs /inventory
 */

import { chromium } from "@playwright/test";

const BASE = process.env.ECDAT_UI ?? "http://localhost:3000";
const target = process.argv[2] ?? "/";

const browser = await chromium.launch({ channel: "chrome" });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });

page.on("console", (message) => {
  if (message.type() !== "error" && message.type() !== "warning") return;
  console.log(`\n===== ${message.type().toUpperCase()} =====`);
  console.log(message.text());
  const location = message.location();
  if (location?.url) console.log(`  at ${location.url}:${location.lineNumber}`);
});

page.on("pageerror", (error) => {
  console.log("\n===== PAGEERROR =====");
  console.log(error.stack ?? error.message);
});

await page.goto(`${BASE}${target}`, { waitUntil: "networkidle", timeout: 90000 });
await page.waitForTimeout(2500);

await browser.close();
