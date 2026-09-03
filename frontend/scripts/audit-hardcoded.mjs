/**
 * ECDAT Frontend – Hardcoded-Data Audit
 * Exit 0 = clean. Exit 1 = suspicious patterns found.
 * Usage: node scripts/audit-hardcoded.mjs
 */
import { readFileSync, readdirSync, statSync } from "fs";
import { join, relative } from "path";
import { fileURLToPath } from "url";

const ROOT = join(fileURLToPath(import.meta.url), "../../src");

const SUSPICIOUS_PATTERNS = [
  { re: /\b(mockData|mocked|demoData|fakeAsset|testAsset|demoAsset|staticData)\b/i, label: "Mock/fake data keyword" },
  { re: /\[\s*\{\s*(decision|quantum_exposure|classical_risk|algorithm|migration|risk_score)\s*:/i, label: "Hardcoded analytical object in array literal" },
  { re: /\bconst\s+(nodes|edges)\s*=\s*\[/i, label: "Hardcoded graph nodes/edges array" },
  { re: /\bconst\s+roadmapData\s*=|demoRoadmap\b/i, label: "Hardcoded roadmap data" },
  { re: /risk_score\s*=\s*[0-9]/i, label: "Hardcoded risk_score assignment" },
  { re: /setProgress\s*\(\s*[0-9]+\s*\)/i, label: "Hardcoded progress value" },
  { re: /localStorage\.(set|get)Item\s*\(\s*["'](asset|scan|risk|roadmap|decision)/i, label: "Analytical data in localStorage" },
];

const ANALYTICAL_NUMBERS = [170, 52, 99, 71, 31, 14, 24];

const WHITELISTED = ["components/ui", "components/ecdat/states.tsx", "components/ecdat/layout.tsx",
  "features/dashboard/estate-charts.tsx", "components/shell/command-palette.tsx", "lib/queries.ts"];

function isWL(rel) { return WHITELISTED.some(w => rel.includes(w)); }

function walk(dir, files = []) {
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) {
      if (e === "node_modules" || e === ".next") continue;
      walk(full, files);
    } else if (e.endsWith(".tsx") || e.endsWith(".ts")) files.push(full);
  }
  return files;
}

let findings = 0;
for (const file of walk(ROOT)) {
  const rel = relative(ROOT, file);
  const lines = readFileSync(file, "utf8").split("\n");
  const wl = isWL(rel);
  lines.forEach((line, i) => {
    if (/^\s*(\/\/|\/\*|\*|#)/.test(line)) return;
    for (const { re, label } of SUSPICIOUS_PATTERNS) {
      if (re.test(line)) { console.error(`[SUSPICIOUS] ${rel}:${i+1}  ${label}\n  > ${line.trim()}`); findings++; }
    }
    if (!wl) {
      for (const n of ANALYTICAL_NUMBERS) {
        if (new RegExp(`(=\\s*${n}\\b|:\\s*${n}\\b)(?!px|ms|rem|em|vh|vw|%)`).test(line)) {
          console.warn(`[WARN] ${rel}:${i+1}  Suspicious numeric literal: ${n}\n  > ${line.trim()}`); findings++;
        }
      }
    }
  });
}

console.log("\n" + "=".repeat(72));
if (findings === 0) { console.log("✅  HARDCODED DATA AUDIT PASSED — 0 suspicious patterns found."); process.exit(0); }
else { console.error(`❌  HARDCODED DATA AUDIT FAILED — ${findings} pattern(s) found.`); process.exit(1); }
