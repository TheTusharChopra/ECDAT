/**
 * Render verification for a route: drives the real app in Chrome against the
 * live API and reports anything a screenshot would not tell you.
 *
 * Each viewport gets a brand-new browser context, so every run is a first-time
 * visit with an empty localStorage -- which is also how the theme default is
 * verified rather than assumed.
 *
 * Checks, per viewport width:
 *   - console errors and uncaught exceptions (hydration mismatches included)
 *   - network failures: aborted requests and any response >= 400, with
 *     `/_next/*` chunk failures and API calls called out separately, since a
 *     403'd chunk stops hydration and therefore stops all data loading
 *   - horizontal overflow, with the offending elements named (§25)
 *   - invalid list nesting, which is the usual cause of a hydration mismatch
 *   - skeletons still on screen after the network settles (a stuck query)
 *   - the theme actually applied on first paint
 *
 * Usage:  node scripts/render-probe.mjs [path] [--text] [--shot]
 */
import { chromium } from "@playwright/test";

const args = process.argv.slice(2);
const route = args.find((a) => !a.startsWith("--")) ?? "/";
const wantText = args.includes("--text");
const wantShot = args.includes("--shot");

const BASE = process.env.ECDAT_UI ?? "http://localhost:3000";
const API = process.env.NEXT_PUBLIC_ECDAT_API_URL ?? "http://127.0.0.1:8787";
const VIEWPORTS = [
  { width: 1366, height: 768 },
  { width: 1440, height: 900 },
  { width: 1920, height: 1080 },
];

/**
 * Console noise that is a deliberate part of development and not a defect.
 * Kept deliberately narrow: it matches framework advisories, never anything
 * that could be an application error.
 */
const IGNORED_CONSOLE = [
  /Download the React DevTools/i,
  /\[Fast Refresh\]/i,
];

/**
 * Cancelled navigations and prefetches abort by design -- React Router-style
 * route prefetching produces them on every page. A real failure is a refused
 * connection or a name that will not resolve.
 */
const BENIGN_NET_ERRORS = [/net::ERR_ABORTED/i];

const browser = await chromium.launch({ channel: "chrome" });
const problems = [];
const apiCalls = [];

for (const viewport of VIEWPORTS) {
  const { width } = viewport;
  const context = await browser.newContext({ viewport });
  const page = await context.newPage();

  page.on("console", (msg) => {
    if (msg.type() !== "error") return;
    const text = msg.text();
    if (IGNORED_CONSOLE.some((pattern) => pattern.test(text))) return;
    problems.push(`[${width}] console: ${text.slice(0, 400)}`);
  });

  page.on("pageerror", (err) => problems.push(`[${width}] pageerror: ${err.message.slice(0, 400)}`));

  page.on("requestfailed", (request) => {
    const reason = request.failure()?.errorText ?? "unknown";
    if (BENIGN_NET_ERRORS.some((pattern) => pattern.test(reason))) return;
    problems.push(`[${width}] request failed (${reason}): ${request.url()}`);
  });

  page.on("response", (response) => {
    const url = response.url();
    const status = response.status();

    if (url.startsWith(API)) {
      apiCalls.push({ width, status, url: url.slice(API.length) || "/" });
    }
    if (status < 400) return;

    // Called out by kind: a 403 on a chunk is the failure that silently prevents
    // every other request from ever happening.
    const kind = url.includes("/_next/")
      ? "STATIC ASSET"
      : url.startsWith(API)
        ? "API"
        : "request";
    problems.push(`[${width}] ${kind} ${status}: ${url}`);
  });

  await page.goto(`${BASE}${route}`, { waitUntil: "networkidle", timeout: 90000 });
  await page.waitForTimeout(1500);

  const report = await page.evaluate(() => {
    const doc = document.documentElement;
    const describe = (el) =>
      `${el.tagName.toLowerCase()}${el.className ? "." + String(el.className).split(/\s+/).slice(0, 3).join(".") : ""}`;

    const offenders = [];
    if (doc.scrollWidth > doc.clientWidth + 1) {
      for (const el of document.querySelectorAll("*")) {
        const r = el.getBoundingClientRect();
        if (r.right > doc.clientWidth + 2 && r.width > 4) offenders.push(`${describe(el)} right=${Math.round(r.right)}`);
        if (offenders.length > 5) break;
      }
    }

    const nesting = [];
    for (const el of document.querySelectorAll("li li, li > ul, li > ol, p p, button button, a a")) {
      const path = [];
      let node = el;
      while (node && node !== document.body) {
        path.unshift(describe(node));
        node = node.parentElement;
      }
      nesting.push(`${path.slice(-4).join(" > ")} :: "${el.textContent.trim().slice(0, 50)}"`);
    }

    let stored = null;
    try {
      stored = localStorage.getItem("ecdat-theme");
    } catch {
      stored = "(unreadable)";
    }

    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      offenders,
      nesting: nesting.slice(0, 6),
      // A document may carry only one visible `main`. More than one is invalid
      // HTML and leaves a screen reader with two candidates for "the content",
      // which is easy to introduce accidentally by nesting layout wrappers that
      // each think they own the landmark.
      landmarks: {
        main: document.querySelectorAll("main:not([hidden])").length,
        h1: document.querySelectorAll("h1").length,
      },
      skeletons: document.querySelectorAll('[data-slot="skeleton"]').length,
      headings: Array.from(document.querySelectorAll("h1,h2,h3")).map((h) => h.textContent.trim()),
      htmlClass: doc.className,
      isDark: doc.classList.contains("dark"),
      pageBackground: getComputedStyle(document.body).backgroundColor,
      storedTheme: stored,
      text: document.body.innerText,
    };
  });

  if (report.scrollWidth > report.clientWidth + 1) {
    problems.push(
      `[${width}] horizontal overflow ${report.scrollWidth} > ${report.clientWidth}: ${report.offenders.join(" | ")}`,
    );
  }
  for (const n of report.nesting) problems.push(`[${width}] invalid nesting: ${n}`);
  if (report.landmarks.main !== 1) {
    problems.push(`[${width}] ${report.landmarks.main} <main> landmarks (expected exactly 1)`);
  }
  if (report.landmarks.h1 !== 1) {
    problems.push(`[${width}] ${report.landmarks.h1} <h1> elements (expected exactly 1)`);
  }
  if (report.skeletons > 0) problems.push(`[${width}] ${report.skeletons} skeleton(s) still visible after networkidle`);

  // A fresh context has no stored preference, so the theme on screen here is the
  // configured default. Anything but light is a regression on that decision.
  if (report.isDark) {
    problems.push(`[${width}] first load is DARK with no stored preference (html class="${report.htmlClass}")`);
  }

  if (width === 1440) {
    console.log(`=== ${route} ===`);
    console.log(`theme: ${report.isDark ? "dark" : "light"}  body-bg: ${report.pageBackground}  stored: ${report.storedTheme ?? "(none)"}`);
    console.log(`=== HEADINGS (${report.headings.length}) ===`);
    console.log(report.headings.join("\n"));
    if (wantText) {
      console.log("=== BODY TEXT ===");
      console.log(report.text);
    }
    if (wantShot) {
      const slug = route.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "") || "root";
      // Light first: it is the default, so it is what the screenshot should show.
      await page.screenshot({ path: `/tmp/ecdat-${slug}-light.png`, fullPage: true });
      await page.evaluate(() => document.documentElement.classList.add("dark"));
      await page.waitForTimeout(500);
      await page.screenshot({ path: `/tmp/ecdat-${slug}-dark.png`, fullPage: true });
      console.log(`screenshots: /tmp/ecdat-${slug}-{light,dark}.png`);
    }
  }

  await context.close();
}

await browser.close();

console.log(`=== API CALLS (${apiCalls.length}) ===`);
if (apiCalls.length === 0) {
  console.log("none — the page made no request to the API");
} else {
  const seen = new Map();
  for (const call of apiCalls) {
    const key = `${call.status} ${call.url}`;
    seen.set(key, (seen.get(key) ?? 0) + 1);
  }
  for (const [key, count] of seen) console.log(`${key}${count > 1 ? `  (x${count})` : ""}`);
}

console.log("=== PROBLEMS ===");
console.log(problems.length ? problems.join("\n") : "none");
process.exit(problems.length ? 1 : 0);
