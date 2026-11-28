#!/usr/bin/env node
// Write the language routes as real HTML, so /ja and /en are Japanese and
// English before any script runs (crawlers, link previews, no-JS visitors).
//
// public/index.html is the template. Every element with data-i18n gets that
// key's text from public/assets/i18n.js, rendered the way site.js setRich()
// does (`code` spans, | phrase breaks); every data-i18n-attr attribute gets
// its string. Outputs:
//   public/ja.html     Japanese, canonical /ja
//   public/en.html     English,  canonical /en
//   public/index.html  English,  canonical / (x-default), rewritten in place
//                      so its no-JS text always matches i18n.js
//
//   node scripts/prerender.mjs           # write the three files
//   node scripts/prerender.mjs --check   # exit 1 if any is stale

import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import vm from "node:vm";

const PUBLIC = fileURLToPath(new URL("../public/", import.meta.url));
const ORIGIN = "https://kasumi.soramitsu.co.jp";

export async function loadStrings() {
  const source = await readFile(join(PUBLIC, "assets/i18n.js"), "utf8");
  const sandbox = { window: {} };
  vm.runInNewContext(source, sandbox, { filename: "i18n.js", timeout: 1000 });
  const strings = sandbox.window.KASUMI_STRINGS;
  if (!strings?.en || !strings?.ja) throw new Error("i18n.js did not define KASUMI_STRINGS.en and .ja");
  return strings;
}

const escText = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const escAttr = (s) => escText(s).replace(/"/g, "&quot;");

// Same output as setRich() in site.js, as HTML.
export function richHtml(text) {
  if (!text.includes("`") && !text.includes("|")) return escText(text);
  return text
    .split("`")
    .map((part, i) => {
      if (i % 2) return `<code>${escText(part)}</code>`;
      if (!part.includes("|")) return escText(part);
      return part
        .split("|")
        .map((phrase) => {
          const body = phrase.replace(/\s+$/, "");
          return (body ? `<span class="ph">${escText(body)}</span>` : "") + (body !== phrase ? " " : "");
        })
        .join("");
    })
    .join("");
}

// End index (exclusive) of the element whose opening tag ends at `from`,
// counting nested elements with the same tag name.
function closingTag(html, tag, from) {
  const re = new RegExp(`<(/?)${tag}\\b[^>]*>`, "gi");
  re.lastIndex = from;
  let depth = 1;
  for (let m; (m = re.exec(html)); ) {
    if (m[0].endsWith("/>")) continue;
    depth += m[1] ? -1 : 1;
    if (depth === 0) return { innerEnd: m.index, end: re.lastIndex };
  }
  throw new Error(`no closing </${tag}> after offset ${from}`);
}

function setAttr(tag, name, value) {
  const re = new RegExp(`(\\s${name}=")[^"]*(")`);
  return re.test(tag) ? tag.replace(re, `$1${escAttr(value)}$2`) : tag.replace(/\s*\/?>$/, (end) => ` ${name}="${escAttr(value)}"${end}`);
}

export function render(template, strings, lang, canonical) {
  const t = (key) => strings[lang][key] ?? strings.en[key];
  let html = template;

  // 1. Element text, replaced back to front so earlier offsets stay valid.
  const opens = [...html.matchAll(/<([a-zA-Z][\w-]*)\b[^>]*\sdata-i18n="([^"]+)"[^>]*>/g)];
  const spans = opens.map((m) => {
    const innerStart = m.index + m[0].length;
    return { tag: m[1], key: m[2], start: m.index, innerStart, ...closingTag(html, m[1], innerStart) };
  });
  spans.forEach((a, i) => {
    const outer = spans.find((b, j) => j !== i && b.innerStart <= a.start && a.end <= b.innerEnd);
    if (outer) throw new Error(`data-i18n="${a.key}" is nested inside data-i18n="${outer.key}"`);
  });
  let replaced = 0;
  for (const s of [...spans].reverse()) {
    const value = t(s.key);
    if (value === undefined) continue;
    html = html.slice(0, s.innerStart) + richHtml(value) + html.slice(s.innerEnd);
    replaced++;
  }
  const missing = spans.filter((s) => t(s.key) === undefined).map((s) => s.key);
  if (missing.length) throw new Error(`keys missing from i18n.js: ${[...new Set(missing)].join(", ")}`);
  if (replaced !== spans.length) throw new Error(`replaced ${replaced} of ${spans.length} data-i18n elements`);

  // 2. Attributes.
  html = html.replace(/<[a-zA-Z][\w-]*\b[^>]*\sdata-i18n-attr="([^"]+)"[^>]*>/g, (tag, spec) => {
    for (const pair of spec.split(";")) {
      const [name, key] = pair.split(":").map((x) => x?.trim());
      if (!name || !key) continue;
      const value = t(key);
      if (value === undefined) throw new Error(`attribute key missing from i18n.js: ${key}`);
      tag = setAttr(tag, name, value);
    }
    return tag;
  });

  // 3. Document language, canonical and og:url.
  html = html.replace(/<html\b[^>]*>/, (tag) => setAttr(tag, "lang", lang));
  html = html.replace(/<link rel="canonical"[^>]*>/, `<link rel="canonical" href="${canonical}">`);
  html = html.replace(/<meta property="og:url"[^>]*>/, `<meta property="og:url" content="${canonical}">`);
  return html;
}

export async function prerenderTargets() {
  const template = await readFile(join(PUBLIC, "index.html"), "utf8");
  const strings = await loadStrings();
  return [
    { path: join(PUBLIC, "index.html"), expected: render(template, strings, "en", `${ORIGIN}/`) },
    { path: join(PUBLIC, "en.html"), expected: render(template, strings, "en", `${ORIGIN}/en`) },
    { path: join(PUBLIC, "ja.html"), expected: render(template, strings, "ja", `${ORIGIN}/ja`) },
  ];
}

async function main() {
  const check = process.argv.includes("--check");
  let stale = 0;
  for (const { path, expected } of await prerenderTargets()) {
    let current = "";
    try {
      current = await readFile(path, "utf8");
    } catch {}
    if (current === expected) continue;
    stale++;
    if (check) console.error(`out of date: ${path.slice(PUBLIC.length - "public/".length)}`);
    else {
      await writeFile(path, expected);
      console.log(`wrote ${path.slice(PUBLIC.length - "public/".length)}`);
    }
  }
  if (check && stale) process.exit(1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((err) => {
    console.error(`prerender: ${err.message}`);
    process.exit(1);
  });
}
