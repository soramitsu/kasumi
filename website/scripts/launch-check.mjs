#!/usr/bin/env node
// Checks that must pass before the site takes live payments. Exits 1 and
// lists what is missing. Run: npm run launch-check

import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, relative } from "node:path";
import { loadPlans } from "../lib/plans.js";
import { PAGES, chromeFromIndex, syncPage } from "./sync-chrome.mjs";

const PUBLIC = fileURLToPath(new URL("../public/", import.meta.url));

async function htmlFiles(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await htmlFiles(path)));
    else if (entry.name.endsWith(".html")) out.push(path);
  }
  return out;
}

export async function launchProblems() {
  const problems = [];
  for (const file of await htmlFiles(PUBLIC)) {
    const html = await readFile(file, "utf8");
    if (html.includes("launch-todo")) problems.push(`public/${relative(PUBLIC, file)}: fill in the fields marked launch-todo`);
    if (/soramitsu\.co\.jp\/privacy-policy/.test(html)) problems.push(`public/${relative(PUBLIC, file)}: privacy link should be https://soramitsu.co.jp/privacy`);
  }
  const plans = await loadPlans();
  if (!/^https:\/\/billing\.stripe\.com\//.test(plans.portalUrl || "")) {
    problems.push("public/assets/plans.js: set portalUrl to the Stripe customer-portal login link");
  }
  const chrome = await chromeFromIndex();
  for (const name of PAGES) {
    const page = await readFile(join(PUBLIC, name), "utf8");
    if (syncPage(page, chrome) !== page) problems.push(`public/${name}: header/footer out of date (npm run sync-chrome)`);
  }
  return problems;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const problems = await launchProblems();
  for (const p of problems) console.error(`✗ ${p}`);
  console.log(`
Also confirm by hand (see README "Deploy"):
  - Stripe live account is Soramitsu Co., Ltd.; Stripe Tax has the Japan registration and the
    seller's qualified-invoice number (T + 13 digits) appears on a finalized test invoice
  - customer portal allows cancellation; webhook endpoint subscribed to the events in README
  - Vercel Production env: SITE_URL, STRIPE_SECRET_KEY (live), STRIPE_WEBHOOK_SECRET,
    STRIPE_AUTOMATIC_TAX=true, STRIPE_REQUIRE_TERMS=true, NOTIFY_WEBHOOK_URL
  - counsel has reviewed /legal/support-terms and /legal/tokushoho; tax adviser has checked a real invoice`);
  if (problems.length) {
    console.error(`\n${problems.length} launch blocker(s).`);
    process.exit(1);
  }
  console.log("\nNo automated launch blockers.");
}
