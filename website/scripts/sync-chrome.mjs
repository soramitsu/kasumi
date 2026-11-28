#!/usr/bin/env node
// Copy the site header and footer from public/index.html into the secondary
// pages, between <!--SITE-HEADER-->…<!--/SITE-HEADER--> and
// <!--SITE-FOOTER-->…<!--/SITE-FOOTER--> markers. In-page anchors (#why)
// become links to the home page (/#why).
//
//   node scripts/sync-chrome.mjs           # rewrite pages
//   node scripts/sync-chrome.mjs --check   # exit 1 if any page is out of date

import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const PUBLIC = fileURLToPath(new URL("../public/", import.meta.url));
export const PAGES = ["thanks.html", "404.html", "legal/tokushoho.html", "legal/support-terms.html", "legal/support-terms-2026-11-27.html"];

function block(html, tag) {
  const match = html.match(new RegExp(`<${tag}\\b[^>]*class="site-${tag}"[\\s\\S]*?</${tag}>`));
  if (!match) throw new Error(`index.html has no <${tag} class="site-${tag}">`);
  // Secondary pages are not language-routed: switch language in place.
  return match[0].replace(/href="#(?!main")/g, 'href="/#').replace(/href="\/(en|ja)"/g, 'href="?lang=$1"');
}

export function syncPage(page, chrome) {
  let out = page;
  for (const [name, content] of Object.entries(chrome)) {
    const open = `<!--SITE-${name}-->`;
    const close = `<!--/SITE-${name}-->`;
    const start = out.indexOf(open);
    if (start < 0) throw new Error(`missing ${open}`);
    const end = out.indexOf(close, start);
    const tail = end < 0 ? start + open.length : end + close.length;
    out = `${out.slice(0, start)}${open}\n${content}\n${close}${out.slice(tail)}`;
  }
  return out;
}

export async function chromeFromIndex() {
  const index = await readFile(join(PUBLIC, "index.html"), "utf8");
  return { HEADER: block(index, "header"), FOOTER: block(index, "footer") };
}

async function main() {
  const check = process.argv.includes("--check");
  const chrome = await chromeFromIndex();
  let stale = 0;
  for (const name of PAGES) {
    const path = join(PUBLIC, name);
    const before = await readFile(path, "utf8");
    const after = syncPage(before, chrome);
    if (after === before) continue;
    stale++;
    if (check) console.error(`out of date: public/${name}`);
    else {
      await writeFile(path, after);
      console.log(`updated public/${name}`);
    }
  }
  if (check && stale) process.exit(1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((err) => {
    console.error(`sync-chrome: ${err.message}`);
    process.exit(1);
  });
}
