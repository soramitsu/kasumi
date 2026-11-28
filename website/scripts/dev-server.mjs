#!/usr/bin/env node
// Local preview of the Kasumi website: static files from public/ with the
// same clean URLs and security headers as vercel.json, plus the /api
// functions. With --fake-stripe, an in-memory Stripe stands in for the real
// API and a local page stands in for Stripe-hosted Checkout.
//
//   node scripts/dev-server.mjs --fake-stripe            # no Stripe account needed
//   STRIPE_SECRET_KEY=sk_test_... node scripts/dev-server.mjs   # real test mode
//
// Options: --port N (default 4318), --host H (default 127.0.0.1).

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { handleCheckout } from "../lib/checkout.js";
import { handleWebhook } from "../lib/webhook.js";
import { stripeClient } from "../lib/stripe.js";
import { loadPlans } from "../lib/plans.js";
import { applyChanges, planChanges } from "./stripe-setup.mjs";
import { fakeStripe } from "../test/fake-stripe.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PUBLIC = join(ROOT, "public");
const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".woff2": "font/woff2",
};

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const port = Number(arg("--port", "4318"));
const host = arg("--host", "127.0.0.1");
const useFake = process.argv.includes("--fake-stripe");
const origin = `http://${host}:${port}`;

const vercel = JSON.parse(await readFile(join(ROOT, "vercel.json"), "utf8"));
const rewrites = new Map((vercel.rewrites || []).map((r) => [r.source, r.destination]));
const globalHeaders = Object.fromEntries(
  (vercel.headers || []).filter((h) => h.source === "/(.*)").flatMap((h) => h.headers.map((x) => [x.key, x.value])),
);

const env = { ...process.env, SITE_URL: process.env.SITE_URL || origin };
let fetchImpl;
if (useFake) {
  const fake = fakeStripe({ checkoutOrigin: origin });
  fetchImpl = fake.fetchImpl;
  env.STRIPE_SECRET_KEY = "sk_test_fake_local_only";
  env.STRIPE_API_BASE = "https://fake-stripe.invalid";
  env.STRIPE_CHECKOUT_ORIGIN = origin;
  env.STRIPE_REQUIRE_TERMS ??= "true";
  env.STRIPE_AUTOMATIC_TAX ??= "true";
  const client = stripeClient({ secretKey: env.STRIPE_SECRET_KEY, apiBase: env.STRIPE_API_BASE, fetchImpl });
  const actions = await planChanges(client, await loadPlans());
  await applyChanges(client, actions, () => {});
  console.log(`fake Stripe seeded with ${fake.prices.size} prices from public/assets/plans.js`);
  globalThis.__fakeStripe = fake;
}
// lib/stripe.js reads these from process.env.
Object.assign(process.env, env);

function fakeCheckoutPage(id) {
  const session = globalThis.__fakeStripe?.sessions.find((s) => s.id === id);
  if (!session) return null;
  const p = session.params;
  const price = globalThis.__fakeStripe.prices.get(p.line_items[0].price);
  const success = p.success_url.replace("{CHECKOUT_SESSION_ID}", id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fake Stripe Checkout</title>
<body><main>
<h1>Fake Stripe Checkout (local only)</h1>
<p>${esc(price.nickname)} — ${esc(price.unit_amount)} ${esc(price.currency.toUpperCase())} per ${esc(price.recurring.interval)}, tax ${esc(p.automatic_tax?.enabled === "true" ? "calculated by Stripe Tax" : "not calculated")}.</p>
<p>locale=${esc(p.locale)} · billing address ${esc(p.billing_address_collection)} · tax ID collection ${esc(p.tax_id_collection?.enabled)} · terms ${esc(p.consent_collection?.terms_of_service || "not required")}</p>
<p><a id="pay" href="${esc(success)}">Pay (simulated)</a> · <a id="cancel" href="${esc(p.cancel_url)}">Back</a></p>
</main></body></html>`;
}

async function toRequest(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks);
  return new Request(`${origin}${req.url}`, {
    method: req.method,
    headers: Object.entries(req.headers).flatMap(([k, v]) => (Array.isArray(v) ? v.map((x) => [k, x]) : [[k, v]])),
    body: ["GET", "HEAD"].includes(req.method) ? undefined : body,
  });
}

async function sendResponse(res, response) {
  const headers = { ...globalHeaders };
  response.headers.forEach((v, k) => (headers[k] = v));
  res.writeHead(response.status, headers);
  res.end(Buffer.from(await response.arrayBuffer()));
}

async function resolveStatic(pathname) {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  const candidates = decoded.endsWith("/")
    ? [join(decoded, "index.html")]
    : extname(decoded)
      ? [decoded]
      : [`${decoded}.html`, join(decoded, "index.html"), decoded];
  for (const candidate of candidates) {
    const full = normalize(join(PUBLIC, candidate));
    if (full !== PUBLIC && !full.startsWith(PUBLIC + sep)) return null;
    try {
      if ((await stat(full)).isFile()) return full;
    } catch {}
  }
  return null;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, origin);
  try {
    if (url.pathname === "/api/checkout" || url.pathname === "/api/webhook") {
      const handler = url.pathname === "/api/checkout" ? handleCheckout : handleWebhook;
      const response = await handler(await toRequest(req), { env, fetchImpl });
      console.log(`${req.method} ${url.pathname} → ${response.status}`);
      return sendResponse(res, response);
    }
    const fake = url.pathname.match(/^\/c\/pay\/(cs_test_[a-z0-9]+)$/);
    if (useFake && fake) {
      const page = fakeCheckoutPage(fake[1]);
      if (page) return sendResponse(res, new Response(page, { headers: { "Content-Type": TYPES[".html"] } }));
    }
    // vercel.json cleanUrls: /thanks.html redirects to /thanks.
    if (url.pathname.endsWith(".html")) {
      const clean = url.pathname.replace(/(index)?\.html$/, "");
      return sendResponse(res, new Response(null, { status: 308, headers: { Location: clean + url.search } }));
    }
    const file = await resolveStatic(rewrites.get(url.pathname) || url.pathname);
    if (!file) {
      const notFound = await resolveStatic("/404");
      const body = notFound ? await readFile(notFound) : "Not found";
      return sendResponse(res, new Response(body, { status: 404, headers: { "Content-Type": TYPES[".html"] } }));
    }
    const body = await readFile(file);
    return sendResponse(
      res,
      new Response(req.method === "HEAD" ? null : body, {
        headers: { "Content-Type": TYPES[extname(file)] || "application/octet-stream", "Cache-Control": "no-cache" },
      }),
    );
  } catch (err) {
    console.error(err);
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("dev server error");
  }
});

server.listen(port, host, () => {
  console.log(`Kasumi website at ${origin}/ (${useFake ? "fake Stripe" : env.STRIPE_SECRET_KEY ? "Stripe API" : "no Stripe key: checkout returns 500"})`);
});
