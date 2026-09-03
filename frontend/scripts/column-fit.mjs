/**
 * Which inventory columns are readable without scrolling sideways.
 *
 * The table is allowed to scroll horizontally -- nineteen columns will not fit a
 * laptop otherwise -- but the columns that carry the page's argument (the two
 * risk axes, the decision, the strategy and the priority) should be visible
 * before anyone reaches for the scrollbar. This measures that, per viewport,
 * instead of guessing from a screenshot.
 *
 *   node scripts/column-fit.mjs
 */

import { chromium } from "@playwright/test";

const UI = process.env.ECDAT_UI ?? "http://localhost:3000";
const VIEWPORTS = [
  { width: 1366, height: 768 },
  { width: 1440, height: 900 },
  { width: 1920, height: 1080 },
];

/** The columns whose visibility the page's stated purpose depends on. */
const SPINE = ["Classical risk", "Quantum exposure", "Decision", "Strategy", "Priority"];

const browser = await chromium.launch({ channel: "chrome" });
let failures = 0;

/** Measure which header cells fall inside the table's own scroll container. */
const measure = (page) =>
  page.$$eval("thead th", (cells) => {
    // The scroll container is whichever ancestor actually clips the table.
    let scroller = cells[0]?.closest("table")?.parentElement ?? null;
    while (scroller && scroller.scrollWidth <= scroller.clientWidth + 1) {
      scroller = scroller.parentElement;
    }
    const limit = scroller ? scroller.getBoundingClientRect().right : window.innerWidth;
    return {
      limit: Math.round(limit),
      scrollWidth: scroller?.scrollWidth ?? null,
      clientWidth: scroller?.clientWidth ?? null,
      columns: cells.map((cell) => ({
        label: cell.innerText.trim().replace(/\s+/g, " "),
        width: Math.round(cell.getBoundingClientRect().width),
        right: Math.round(cell.getBoundingClientRect().right),
        visible: cell.getBoundingClientRect().right <= limit + 1,
      })),
    };
  });

const report = (title, measured) => {
  const columns = measured.columns;
  const visible = columns.filter((column) => column.visible).map((column) => column.label);
  const clipped = columns.filter((column) => !column.visible).map((column) => column.label);
  const missing = SPINE.filter((label) => !visible.includes(label));

  console.log(`\n=== ${title} ===`);
  console.log(`  table  : ${measured.clientWidth}px visible of ${measured.scrollWidth}px total`);
  console.log(
    `  widths : ${columns.filter((c) => c.label).map((c) => `${c.label} ${c.width}`).join("  ")}`,
  );
  console.log(`  visible: ${visible.filter(Boolean).join(" | ")}`);
  console.log(`  clipped: ${clipped.filter(Boolean).join(" | ") || "(none)"}`);
  if (missing.length === 0) {
    console.log("  PASS  the full decision spine is visible without scrolling");
    return true;
  }
  console.log(`  MISS  spine columns behind the scroll: ${missing.join(", ")}`);
  return false;
};

for (const viewport of VIEWPORTS) {
  const page = await browser.newPage({ viewport });
  await page.goto(`${UI}/inventory`, { waitUntil: "networkidle", timeout: 90000 });
  await page.waitForSelector("tbody tr", { timeout: 30000 });
  await page.waitForTimeout(400);

  const fits = report(`${viewport.width}x${viewport.height}`, await measure(page));

  // The sidebar collapses (the app registers Cmd/Ctrl+B for it). At the smallest
  // viewport that is the difference between reading the whole spine and scrolling
  // for the last column, so it is worth measuring rather than assuming.
  if (!fits) {
    await page.keyboard.press("ControlOrMeta+b");
    await page.waitForTimeout(500);
    const collapsed = report(`${viewport.width}x${viewport.height} · sidebar collapsed`, await measure(page));
    if (!collapsed) failures += 1;
  }

  await page.close();
}

await browser.close();
console.log(`\n=== ${failures === 0 ? "SPINE READABLE AT EVERY VIEWPORT (collapsing the sidebar where needed)" : `${failures} VIEWPORT(S) CLIP THE SPINE EVEN COLLAPSED`} ===`);
process.exit(failures === 0 ? 0 : 1);
