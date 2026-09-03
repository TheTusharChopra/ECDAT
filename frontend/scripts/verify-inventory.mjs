/**
 * Page 1 live-data verification: /inventory against the running API.
 *
 * Nothing here is asserted against a hard-coded figure. Every expectation is
 * read from the API at run time and compared with what the browser rendered, so
 * the script keeps working when the demo estate is rescanned -- and so a passing
 * run means "the screen agrees with the backend", not "the screen agrees with a
 * number someone typed into a test".
 *
 *   node scripts/verify-inventory.mjs
 */

import { chromium } from "@playwright/test";

const UI = process.env.ECDAT_UI ?? "http://localhost:3000";
const API = process.env.ECDAT_API ?? "http://127.0.0.1:8787";

const BANNED = [
  "Not yet implemented",
  "This screen is not built yet",
  "Placeholder route",
  "Nothing on this page is analysis output",
  "coming soon",
];

let failures = 0;
const step = (n, text) => console.log(`\n--- STEP ${n}: ${text}`);
const ok = (text) => console.log(`  PASS  ${text}`);
const bad = (text) => {
  failures += 1;
  console.log(`  FAIL  ${text}`);
};
const check = (condition, text) => (condition ? ok(text) : bad(text));

/** Compare display text with an API value: case, hyphens and underscores are presentation. */
const norm = (value) =>
  String(value)
    .toLowerCase()
    .replace(/[-_]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();

const getJson = async (path) => {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(`GET ${path} -> ${response.status}`);
  return response.json();
};

// ---------------------------------------------------------------- steps 1 & 2
step(1, "a scan must exist (POST /scan demo=true if not)");
let baseline;
try {
  baseline = await getJson("/assets?sort=priority&limit=50&offset=0");
  ok(`scan already loaded: ${baseline.scan_id}`);
} catch {
  console.log("  no scan loaded -- running POST /scan {demo:true}");
  const response = await fetch(`${API}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ demo: true }),
  });
  const scan = await response.json();
  ok(`scan created: ${scan.scan_id} (${scan.assets} assets)`);
  baseline = await getJson("/assets?sort=priority&limit=50&offset=0");
}

step(2, "record scan_id and asset count");
console.log(`  scan_id : ${baseline.scan_id}`);
console.log(`  total   : ${baseline.total}`);
console.log(`  matched : ${baseline.matched}`);
console.log(`  returned: ${baseline.count} (limit ${baseline.limit}, view ${baseline.view})`);
check(baseline.total > 0, `estate is not empty (${baseline.total} assets)`);

const browser = await chromium.launch({ channel: "chrome" });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();

const apiCalls = [];
const consoleErrors = [];
const badResponses = [];
page.on("request", (request) => {
  if (request.url().startsWith(API)) apiCalls.push(request.url().slice(API.length));
});
page.on("response", (response) => {
  if (response.url().startsWith(API) && response.status() >= 400) {
    badResponses.push(`${response.status()} ${response.url().slice(API.length)}`);
  }
});
page.on("console", (message) => {
  if (message.type() === "error" && !/DevTools/i.test(message.text())) {
    consoleErrors.push(message.text().slice(0, 160));
  }
});
page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${error.message}`));

const open = async (url) => {
  apiCalls.length = 0;
  await page.goto(`${UI}${url}`, { waitUntil: "networkidle", timeout: 90000 });
  await page.waitForSelector("tbody tr", { timeout: 30000 }).catch(() => {});
  await page.waitForTimeout(400);
};

/** The count line, as rendered. */
const readCounts = async () => {
  const text = await page.locator("main").innerText();
  const range = text.match(/([\d,]+)–([\d,]+)\s+of\s+([\d,]+)\s+matched/);
  const estate = text.match(/·\s+([\d,]+)\s+in the estate/);
  const view = text.match(/view=(summary|full)/);
  const num = (value) => (value ? Number(value.replace(/,/g, "")) : undefined);
  return {
    first: num(range?.[1]),
    last: num(range?.[2]),
    matched: num(range?.[3]),
    total: num(estate?.[1]),
    view: view?.[1],
    text,
  };
};

/** Asset ids in rendered row order, taken from each row's asset link. */
const readRowIds = async () =>
  page.$$eval("tbody tr a[href^='/assets/']", (anchors) =>
    anchors.map((anchor) => anchor.getAttribute("href").replace("/assets/", "")),
  );

const readRowTexts = async () =>
  page.$$eval("tbody tr", (rows) => rows.map((row) => row.innerText));

// -------------------------------------------------------------------- step 3
step(3, "open /inventory");
await open("/inventory");
check(page.url().endsWith("/inventory"), `loaded ${page.url()}`);

// -------------------------------------------------------------------- step 4
step(4, "capture the actual GET /assets request the page made");
const tableCall = apiCalls.find((url) => /^\/assets\?/.test(url) && !url.includes("limit=1000"));
check(Boolean(tableCall), `page requested the API: ${tableCall ?? "NONE"}`);
console.log(`  all API calls: ${[...new Set(apiCalls)].join("  ")}`);
check(
  !apiCalls.some((url) => url.includes("view=full")),
  "no view=full request while both full-only columns are hidden",
);
const live = tableCall ? await getJson(tableCall) : baseline;

// -------------------------------------------------------------------- step 5
step(5, "displayed total / matched / row count / row values match the API");
const counts = await readCounts();
check(counts.matched === live.matched, `matched: UI ${counts.matched} = API ${live.matched}`);
check(
  counts.total === undefined ? live.matched === live.total : counts.total === live.total,
  `total: UI ${counts.total ?? "(equal to matched, so not shown)"} = API ${live.total}`,
);
check(counts.view === live.view, `projection: UI view=${counts.view} = API view=${live.view}`);

const rowIds = await readRowIds();
check(
  rowIds.length === live.count,
  `row count: ${rowIds.length} rendered = ${live.count} returned by the API`,
);
const apiIds = live.assets.map((asset) => asset.asset_id);
check(
  JSON.stringify(rowIds) === JSON.stringify(apiIds),
  "rendered rows are the API's assets, in the API's order",
);
check(
  counts.first === live.offset + 1 && counts.last === live.offset + live.count,
  `range line: ${counts.first}–${counts.last} matches offset ${live.offset} + count ${live.count}`,
);

const rowTexts = await readRowTexts();
const FIELDS = [
  "asset_name",
  "algorithm_label",
  "cryptographic_role",
  "application",
  "library",
  "migration_decision",
  "recommended_strategy",
  "priority_band",
  "confidence",
];
for (let index = 0; index < Math.min(5, rowTexts.length); index += 1) {
  const asset = live.assets[index];
  const text = norm(rowTexts[index]);
  const present = [];
  const missing = [];
  for (const field of FIELDS) {
    const value = asset[field];
    if (value === null || value === undefined || value === "") continue;
    (text.includes(norm(value)) ? present : missing).push(`${field}=${value}`);
  }
  if (missing.length === 0 && present.length >= 5) {
    ok(`row ${index + 1} (${asset.asset_id}): ${present.length} values verified — ${present.join(", ")}`);
  } else {
    bad(`row ${index + 1} (${asset.asset_id}): missing ${missing.join(", ") || "(too few fields)"}`);
  }
}

// --------------------------------------------------------------- steps 6 & 7
step(6, "apply a real server-side filter (quantum_exposure=critical)");
await open("/inventory?quantum_exposure=critical");
const filteredCall = apiCalls.find(
  (url) => /^\/assets\?/.test(url) && url.includes("quantum_exposure=critical") && !url.includes("limit=1000"),
);
check(Boolean(filteredCall), `filter reached the API in the URL: ${filteredCall ?? "NONE"}`);
const filtered = filteredCall ? await getJson(filteredCall) : null;

step(7, "the API's matched count changes, and the UI shows the API's number");
const filteredCounts = await readCounts();
check(
  filtered !== null && filtered.matched < live.matched,
  `matched narrowed: ${live.matched} unfiltered -> ${filtered?.matched} filtered`,
);
check(
  filteredCounts.matched === filtered?.matched,
  `UI shows the API's matched: ${filteredCounts.matched} = ${filtered?.matched}`,
);
check(
  filteredCounts.total === live.total,
  `estate total still reported: ${filteredCounts.total} = ${live.total}`,
);
const filteredRows = await readRowIds();
check(
  JSON.stringify(filteredRows) === JSON.stringify(filtered?.assets.map((asset) => asset.asset_id)),
  "filtered rows are the API's filtered assets, in order",
);

// --------------------------------------------------------------- steps 8 & 9
step(8, "apply a page-only filter (role — the API has no such parameter)");
const roleCounts = new Map();
for (const asset of live.assets) {
  if (!asset.cryptographic_role) continue;
  roleCounts.set(asset.cryptographic_role, (roleCounts.get(asset.cryptographic_role) ?? 0) + 1);
}
const narrowing = [...roleCounts.entries()].find(([, count]) => count > 0 && count < live.count);
if (!narrowing) {
  bad("no role value on the page narrows it, so the page-only path cannot be exercised");
} else {
  const [role, expected] = narrowing;
  await open(`/inventory?role=${encodeURIComponent(role)}`);
  const roleCall = apiCalls.find((url) => /^\/assets\?/.test(url) && !url.includes("limit=1000"));
  check(
    Boolean(roleCall) && !roleCall.includes("role="),
    `the API request does NOT carry role= (it would 400): ${roleCall}`,
  );
  const roleRows = await readRowIds();
  check(
    roleRows.length === expected,
    `page narrowed in the browser: ${roleRows.length} rows = ${expected} rows with role ${role}`,
  );

  step(9, "the page-only filter is labelled page-only");
  const roleText = (await readCounts()).text;
  check(
    /shown after a page-only filter/.test(roleText),
    "count line states the rows shown are after a page-only filter",
  );
  check(
    new RegExp(`${roleRows.length}\\s+shown after`).test(roleText.replace(/\n/g, " ")),
    `count line separates ${roleRows.length} shown from the estate-wide matched count`,
  );
  const chip = page.locator("span", { hasText: /^Role/ }).first();
  check(
    (await chip.count()) > 0 && /page/i.test(await chip.innerText()),
    "the active-filter chip for Role carries the 'page' marker",
  );
  check(
    (await readCounts()).matched === live.matched,
    "the estate-wide matched count is unchanged by a page-only filter",
  );
}

// ---------------------------------------------------------- steps 10, 11 & 12
step(10, "change URL parameters manually (the directive's example URL)");
const EXAMPLE = "/inventory?quantum_exposure=critical&decision=hybrid";
await open(EXAMPLE);
const exampleCall = apiCalls.find(
  (url) => /^\/assets\?/.test(url) && url.includes("decision=hybrid") && !url.includes("limit=1000"),
);
check(Boolean(exampleCall), `both filters reached the API: ${exampleCall ?? "NONE"}`);
const example = exampleCall ? await getJson(exampleCall) : null;
const exampleCounts = await readCounts();
check(
  exampleCounts.matched === example?.matched,
  `UI matched ${exampleCounts.matched} = API matched ${example?.matched}`,
);
console.log(`  API echoed filters: ${JSON.stringify(example?.filters)}`);

step(11, "reload the URL");
await page.reload({ waitUntil: "networkidle", timeout: 90000 });
await page.waitForSelector("tbody tr", { timeout: 30000 }).catch(() => {});

step(12, "the exact filter state persists across the reload");
const reloaded = await readCounts();
check(page.url().endsWith(EXAMPLE), `URL preserved: ${page.url()}`);
check(
  reloaded.matched === exampleCounts.matched,
  `matched after reload: ${reloaded.matched} = ${exampleCounts.matched}`,
);
const controls = await page.locator("main").innerText();
check(/Quantum exposure\s*\n?\s*Critical/i.test(controls), "the Quantum exposure control still reads Critical");
check(/Decision\s*\n?\s*HYBRID/i.test(controls), "the Decision control still reads HYBRID");
check(
  JSON.stringify(await readRowIds()) ===
    JSON.stringify(example?.assets.map((asset) => asset.asset_id)),
  "the same rows are restored, in the same order",
);

// -------------------------------------------------------------- steps 13 & 14
step(13, "click an asset row");
const firstId = (await readRowIds())[0];
await page.locator("tbody tr").first().click();
await page.waitForURL(/\/assets\/.+/, { timeout: 30000 });

step(14, "it navigates to /assets/[assetId]");
check(
  page.url().endsWith(`/assets/${firstId}`),
  `navigated to ${page.url().replace(UI, "")} for row asset ${firstId}`,
);

// ------------------------------------------------------------------- step 15
step(15, "zero placeholder text on /inventory");
await open(EXAMPLE);
const body = await page.locator("body").innerText();
const found = BANNED.filter((phrase) => body.toLowerCase().includes(phrase.toLowerCase()));
check(found.length === 0, `banned placeholder strings present: ${found.join(", ") || "none"}`);

// ------------------------------------------------------------------- step 16
// Two of the required columns live outside the summary projection, so they are
// hidden by default. Showing one must refetch with view=full and fill the cells
// from that response -- otherwise the column would be a promise with no data
// behind it.
step(16, "showing a full-only column refetches with view=full and fills the cells");
await open("/inventory");
await page.getByRole("button", { name: /^Columns/ }).click();
await page.getByRole("menuitemcheckbox", { name: /Business criticality/i }).click();
await page.keyboard.press("Escape");
// Poll the recorded call list rather than waiting for the response: the refetch
// starts on the very next render, so a `waitForResponse` registered after the
// click can miss it.
for (let attempt = 0; attempt < 60; attempt += 1) {
  if (apiCalls.some((url) => url.includes("view=full"))) break;
  await page.waitForTimeout(250);
}
await page.waitForTimeout(600);

const fullCall = apiCalls.find((url) => url.includes("view=full"));
check(Boolean(fullCall), `view=full requested only once the column is shown: ${fullCall ?? "NONE"}`);
const fullResponse = fullCall ? await getJson(fullCall) : null;
check(
  (await readCounts()).view === "full",
  "the count line reports the projection actually in use (view=full)",
);

const CRITICALITY_LABEL = {
  "mission-critical": "Mission-critical",
  high: "High",
  important: "Important",
  low: "Low",
  "non-critical": "Non-critical",
};

// Locate the column by its header rather than by a fixed index, so the check
// survives a column being reordered.
const headers = await page.$$eval("thead th", (cells) =>
  cells.map((cell) => cell.innerText.trim()),
);
const criticalityIndex = headers.findIndex((header) => /^Criticality/.test(header));
check(criticalityIndex >= 0, `the Criticality column is now in the header row (index ${criticalityIndex})`);

const cellTexts = await page.$$eval(
  "tbody tr",
  (rows, index) => rows.map((row) => row.children[index]?.innerText.trim() ?? ""),
  criticalityIndex,
);

let recorded = 0;
let explained = 0;
for (let index = 0; index < Math.min(8, cellTexts.length); index += 1) {
  const asset = fullResponse?.assets[index];
  const value = asset?.business_criticality ?? null;
  const cell = cellTexts[index];
  if (value === null) {
    // The API recorded no value, so the cell must say so and must not invent one.
    if (cell === "—") explained += 1;
    else bad(`row ${index + 1}: API business_criticality is null but the cell reads "${cell}"`);
  } else {
    const label = CRITICALITY_LABEL[value] ?? value;
    if (norm(cell).includes(norm(label))) recorded += 1;
    else bad(`row ${index + 1}: API business_criticality ${value} but the cell reads "${cell}"`);
  }
}
check(
  recorded + explained === Math.min(8, cellTexts.length),
  `every Criticality cell agrees with the full projection: ${recorded} with a value, ${explained} reported as not recorded`,
);
console.log(
  `  note: the demo estate declares no business context (context_source=default for all ` +
    `${live.total} assets), so this column is legitimately empty — the cells state that rather than guessing.`,
);

console.log("\n--- browser health");
check(consoleErrors.length === 0, `console errors: ${consoleErrors.length}${consoleErrors.length ? ` -> ${consoleErrors.join(" | ")}` : ""}`);
check(badResponses.length === 0, `failed API responses: ${badResponses.length}${badResponses.length ? ` -> ${badResponses.join(" | ")}` : ""}`);

await browser.close();
console.log(`\n=== ${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`} ===`);
process.exit(failures === 0 ? 0 : 1);
