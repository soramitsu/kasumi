import { test } from "node:test";
import assert from "node:assert/strict";

import { formEncode, signWebhook, stripeClient, verifyWebhook } from "../lib/stripe.js";
import { checkoutPrices, loadPlans, lookupKey } from "../lib/plans.js";
import { configurationProblem, handleCheckout } from "../lib/checkout.js";
import { describeEvent, handleWebhook, kasumiTier, notifyTarget } from "../lib/webhook.js";
import { applyChanges, planChanges } from "../scripts/stripe-setup.mjs";
import { fakeStripe } from "./fake-stripe.js";
import { PAGES, chromeFromIndex, syncPage } from "../scripts/sync-chrome.mjs";
import { readFile } from "node:fs/promises";

const SITE = "https://kasumi.soramitsu.co.jp";
const ENV = {
  SITE_URL: SITE,
  STRIPE_SECRET_KEY: "sk_test_unit",
  STRIPE_API_BASE: "https://fake-stripe.invalid",
  STRIPE_AUTOMATIC_TAX: "true",
  STRIPE_REQUIRE_TERMS: "true",
};
const ATTEMPT = "0f8e5a7c-1d2b-4c3a-9e8f-7a6b5c4d3e2f";

function fixturePlans(overrides = {}) {
  return {
    selfServeOpen: true,
    revision: "r1",
    termsVersion: "2026-11-27",
    currencies: ["JPY", "USD"],
    intervals: ["month", "year"],
    stripeTaxCode: "txcd_20060017",
    tiers: [
      { id: "standard", name: "Standard", summary: { en: "Std", ja: "標準" }, checkout: true,
        price: { JPY: { month: 60000, year: 660000 }, USD: { month: 400, year: 4400 } } },
      { id: "business", name: { en: "Business", ja: "ビジネス" }, checkout: true,
        price: { JPY: { month: 180000, year: 1980000 }, USD: { month: 1200, year: 13200 } } },
      { id: "enterprise", name: "Enterprise", checkout: false,
        price: { JPY: { month: 900000, year: 9900000 }, USD: { month: 6000, year: 66000 } } },
    ],
    ...overrides,
  };
}

async function seeded(plans = fixturePlans()) {
  const fake = fakeStripe();
  const client = stripeClient({ secretKey: ENV.STRIPE_SECRET_KEY, apiBase: ENV.STRIPE_API_BASE, fetchImpl: fake.fetchImpl });
  await applyChanges(client, await planChanges(client, plans), () => {});
  return { fake, client, plans };
}

function checkoutRequest(body, headers = {}) {
  return new Request(`${SITE}/api/checkout`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SITE, ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

// Adds the catalog revision the page would send, unless the body sets one.
function checkout(ctx, body, { headers, env = ENV, plans = ctx.plans, fetchImpl = ctx.fake.fetchImpl } = {}) {
  const withRevision = typeof body === "object" && !("revision" in body) ? { ...body, revision: plans.revision } : body;
  return handleCheckout(checkoutRequest(withRevision, headers), { env, fetchImpl, plans });
}

const priceFor = (fake, tier, interval, currency) =>
  [...fake.prices.values()].find((p) => p.lookup_key === lookupKey(tier, interval, currency));

test("formEncode nests objects and arrays the way Stripe expects", () => {
  const encoded = formEncode({
    mode: "subscription",
    line_items: [{ price: "price_1", quantity: 1 }],
    automatic_tax: { enabled: true },
    skip: undefined,
  }).toString();
  assert.equal(
    decodeURIComponent(encoded),
    "mode=subscription&line_items[0][price]=price_1&line_items[0][quantity]=1&automatic_tax[enabled]=true",
  );
});

test("webhook signatures: valid, tampered, stale, malformed", () => {
  const secret = "whsec_unit";
  const body = JSON.stringify({ id: "evt_1", type: "ping" });
  const header = signWebhook(body, secret);
  assert.equal(verifyWebhook(body, header, secret).id, "evt_1");
  assert.equal(verifyWebhook(body, `${header},v1=${"0".repeat(64)}`, secret).id, "evt_1");
  assert.throws(() => verifyWebhook(body.replace("ping", "pong"), header, secret), /mismatch/);
  assert.throws(() => verifyWebhook(body, signWebhook(body, "whsec_other"), secret), /mismatch/);
  const old = signWebhook(body, secret, Math.floor(Date.now() / 1000) - 3600);
  assert.throws(() => verifyWebhook(body, old, secret), /tolerance/);
  assert.throws(() => verifyWebhook(body, "v1=abc", secret), /malformed/);
  assert.throws(() => verifyWebhook(body, "", secret), /missing/);
});

test("setup creates products and prices once, then reports no changes", async () => {
  const { fake, client, plans } = await seeded();
  assert.equal(fake.products.size, 2, "contact tier gets no product");
  assert.equal(fake.products.get("kasumi_support_standard").tax_code, "txcd_20060017");
  assert.equal(fake.prices.size, 8);
  const stdYearJpy = priceFor(fake, "standard", "year", "jpy");
  assert.equal(stdYearJpy.unit_amount, 660000);
  assert.equal(stdYearJpy.tax_behavior, "exclusive");
  assert.equal(priceFor(fake, "business", "month", "usd").unit_amount, 120000, "USD amounts are in cents");
  assert.deepEqual(await planChanges(client, plans), []);
});

test("setup replaces a changed price and retires a tier that left checkout", async () => {
  const ctx = await seeded();
  const plans = fixturePlans();
  plans.tiers[0].price.JPY.year = 640000;
  plans.tiers[1].checkout = false;
  const actions = await planChanges(ctx.client, plans);
  assert.deepEqual(actions.map((a) => a.kind).sort(), ["archive-price", "create-price", "retire-product"]);
  await applyChanges(ctx.client, actions, () => {});
  const live = [...ctx.fake.prices.values()].filter((p) => p.lookup_key === lookupKey("standard", "year", "jpy"));
  assert.equal(live.length, 1);
  assert.equal(live[0].unit_amount, 640000);
  assert.deepEqual(await planChanges(ctx.client, plans), []);

  // Even with the old catalog, the retired product is refused by Stripe metadata.
  const response = await checkout(ctx, { tier: "business", interval: "year", currency: "jpy" });
  assert.equal(response.status, 404);
});

test("setup archives leftover active prices from an interrupted run", async () => {
  const ctx = await seeded();
  // Simulate a run that moved the lookup key to a new price but died before archiving.
  const old = priceFor(ctx.fake, "standard", "year", "jpy");
  const plans = fixturePlans();
  plans.tiers[0].price.JPY.year = 640000;
  const actions = (await planChanges(ctx.client, plans)).filter((a) => a.kind === "create-price");
  await applyChanges(ctx.client, actions, () => {});
  assert.equal(old.active, true, "old price still active after the interrupted run");
  const next = await planChanges(ctx.client, plans);
  assert.deepEqual(next.map((a) => `${a.kind} ${a.id}`), [`archive-price ${old.id}`]);
  await applyChanges(ctx.client, next, () => {});
  assert.deepEqual(await planChanges(ctx.client, plans), []);
  const params = (await planChanges(ctx.client, fixturePlans({ tiers: [{ ...plans.tiers[0], price: { JPY: { month: 1, year: 2 }, USD: { month: 1, year: 2 } } }] })))
    .find((a) => a.kind === "create-price").params;
  assert.equal(params.billing_scheme, "per_unit");
  assert.equal(params.recurring.usage_type, "licensed");
});

test("the setup CLI refuses to send a live key to an overridden API host", async () => {
  const { execFile } = await import("node:child_process");
  const run = (env) =>
    new Promise((resolve) =>
      execFile(process.execPath, [new URL("../scripts/stripe-setup.mjs", import.meta.url).pathname, "--live"], { env: { PATH: process.env.PATH, ...env } }, (err, stdout, stderr) =>
        resolve({ code: err ? err.code : 0, stderr }),
      ),
    );
  const result = await run({ STRIPE_SECRET_KEY: "sk_live_notreal", STRIPE_API_BASE: "http://127.0.0.1:9" });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /Refusing to send a live-mode key/);
});

test("setup finds Kasumi products beyond the first page", async () => {
  const ctx = await seeded();
  for (let i = 0; i < 120; i++) {
    ctx.fake.products.set(`prod_other_${i}`, { id: `prod_other_${i}`, active: true, metadata: {} });
  }
  ctx.fake.products.set("kasumi_support_legacy", {
    id: "kasumi_support_legacy", active: true, metadata: { kasumi_tier: "legacy", kasumi_checkout: "true" },
  });
  const actions = await planChanges(ctx.client, ctx.plans);
  assert.deepEqual(actions.map((a) => `${a.kind} ${a.id}`), ["retire-product kasumi_support_legacy"]);
});

test("checkout creates a subscription session from the server-side price", async () => {
  const ctx = await seeded();
  const response = await checkout(ctx, {
    tier: "business", interval: "year", currency: "JPY", locale: "ja", attempt: ATTEMPT, amount: 1,
  });
  assert.equal(response.status, 200);
  const { url } = await response.json();
  assert.match(url, /^https:\/\/checkout\.stripe\.com\/c\/pay\/cs_test_/);
  const params = ctx.fake.sessions.at(-1).params;
  const price = ctx.fake.prices.get(params.line_items[0].price);
  assert.equal(price.unit_amount, 1980000);
  assert.equal(price.currency, "jpy");
  assert.equal(params.mode, "subscription");
  assert.equal(params.currency, "jpy");
  assert.equal(params.adaptive_pricing.enabled, "false");
  assert.equal(params.locale, "ja");
  assert.equal(params.success_url, `${SITE}/thanks?lang=ja`, "no session id in the return URL");
  assert.equal(params.cancel_url, `${SITE}/ja?interval=year&currency=JPY#support`, "cancel keeps the selection");
  assert.deepEqual(params.payment_method_types, ["card"], "matches the legal notice");
  assert.equal(params.automatic_tax.enabled, "true");
  assert.equal(params.tax_id_collection.enabled, "true");
  assert.equal(params.name_collection.business.enabled, "true");
  assert.equal(params.billing_address_collection, "required");
  assert.equal(params.consent_collection.terms_of_service, "required");
  assert.match(params.custom_text.terms_of_service_acceptance.message, /事業目的で申し込み/);
  assert.match(params.custom_text.terms_of_service_acceptance.message, /\/legal\/support-terms-2026-11-27\)/);
  assert.match(params.custom_text.submit.message, /年額一括払い.*service@soramitsu\.co\.jp/);
  assert.equal(params.client_reference_id, ATTEMPT);
  assert.equal(params.subscription_data.metadata.kasumi_tier, "business");
  assert.equal(params.subscription_data.metadata.kasumi_terms, "2026-11-27");
  const call = ctx.fake.calls.at(-1);
  assert.equal(call.headers["Idempotency-Key"], `kasumi-checkout-${ATTEMPT}-business-year-jpy-ja`);
  assert.equal(call.headers["Stripe-Version"], "2026-02-25.clover");
});

test("a repeated attempt gets the same Checkout Session back", async () => {
  const ctx = await seeded();
  const body = { tier: "standard", interval: "month", currency: "jpy", locale: "ja", attempt: ATTEMPT };
  const [a, b] = await Promise.all([checkout(ctx, body), checkout(ctx, body)]);
  assert.equal((await a.json()).url, (await b.json()).url);
  assert.equal(ctx.fake.sessions.length, 1);
  const other = await checkout(ctx, { ...body, interval: "year" });
  assert.equal(other.status, 200, "a different selection is a different attempt key");
  assert.equal(ctx.fake.sessions.length, 2);
});

test("checkout ignores the Host header when building return URLs", async () => {
  const ctx = await seeded();
  const request = new Request("https://evil.example/api/checkout", {
    method: "POST",
    headers: { "Content-Type": "application/json", Host: "evil.example" },
    body: JSON.stringify({ tier: "standard", interval: "month", currency: "usd", revision: "r1" }),
  });
  const response = await handleCheckout(request, { env: ENV, fetchImpl: ctx.fake.fetchImpl, plans: ctx.plans });
  assert.equal(response.status, 200);
  const params = ctx.fake.sessions.at(-1).params;
  assert.ok(params.success_url.startsWith(`${SITE}/thanks`));
  assert.match(params.custom_text.submit.message, /^Monthly support subscription/);
});

test("checkout rejects bad input, foreign origins and contact tiers", async () => {
  const ctx = await seeded();
  const ok = { tier: "standard", interval: "month", currency: "usd" };
  const status = async (body, opts) => (await checkout(ctx, body, opts)).status;
  assert.equal(await status({ ...ok, tier: "Standard" }), 400);
  assert.equal(await status({ ...ok, interval: "week" }), 400);
  assert.equal(await status({ ...ok, currency: "eur" }), 400);
  assert.equal(await status("not json"), 400);
  assert.equal(await status({ ...ok, pad: "x".repeat(2000) }), 413);
  assert.equal(await status(ok, { headers: { "Content-Length": "5000" } }), 413);
  assert.equal(await status({ ...ok, revision: "r0" }), 409, "page rendered from an older catalog");
  assert.equal(await status({ ...ok, revision: undefined }), 409, "revision is required");
  assert.equal(await status(ok, { headers: { Origin: "https://evil.example" } }), 403);
  assert.equal(await status(ok, { headers: { "Content-Type": "text/plain" } }), 415);
  assert.equal(await status({ tier: "enterprise", interval: "year", currency: "jpy" }), 404);
  assert.equal(await status({ tier: "nosuch", interval: "year", currency: "jpy" }), 404);
  const get = await handleCheckout(new Request(`${SITE}/api/checkout`), { env: ENV, plans: ctx.plans });
  assert.equal(get.status, 405);
});

test("checkout is closed server-side while selfServeOpen is false", async () => {
  const ctx = await seeded();
  const closed = fixturePlans({ selfServeOpen: false });
  const response = await checkout(ctx, { tier: "standard", interval: "month", currency: "jpy" }, { plans: closed });
  assert.equal(response.status, 403);
  assert.equal(ctx.fake.sessions.length, 0);
});

test("checkout refuses a Stripe price that disagrees with plans.js", async () => {
  const body = { tier: "standard", interval: "month", currency: "usd" };
  const tamper = async (mutate) => {
    const ctx = await seeded();
    mutate(ctx);
    return (await checkout(ctx, body)).status;
  };
  assert.equal(await tamper(({ fake }) => (priceFor(fake, "standard", "month", "usd").metadata.kasumi_tier = "business")), 404);
  assert.equal(await tamper(({ fake }) => (priceFor(fake, "standard", "month", "usd").unit_amount = 100)), 404);
  assert.equal(await tamper(({ fake }) => (priceFor(fake, "standard", "month", "usd").tax_behavior = "inclusive")), 404);
  assert.equal(await tamper(({ plans }) => (plans.tiers[0].price.USD.month = 500)), 404, "catalog changed, Stripe not yet");
  assert.equal(await tamper(({ fake }) => (priceFor(fake, "standard", "month", "usd").recurring.usage_type = "metered")), 404);
  assert.equal(await tamper(({ fake }) => (priceFor(fake, "standard", "month", "usd").transform_quantity = { divide_by: 10, round: "up" })), 404);
  assert.equal(await tamper(({ fake }) => (priceFor(fake, "standard", "month", "usd").billing_scheme = "tiered")), 404);
});

test("an oversized streamed body is refused without buffering it all", async () => {
  const ctx = await seeded();
  let pulled = 0;
  const stream = new ReadableStream({
    pull(controller) {
      pulled++;
      if (pulled > 1000) controller.close();
      else controller.enqueue(new TextEncoder().encode("x".repeat(512)));
    },
  });
  const request = new Request(`${SITE}/api/checkout`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SITE },
    body: stream,
    duplex: "half",
  });
  const response = await handleCheckout(request, { env: ENV, fetchImpl: ctx.fake.fetchImpl, plans: ctx.plans });
  assert.equal(response.status, 413);
  assert.ok(pulled < 10, `stopped reading after ${pulled} chunks`);
});

test("checkout fails closed on configuration and provider problems", async () => {
  const ctx = await seeded();
  const body = { tier: "standard", interval: "month", currency: "usd" };
  assert.equal((await checkout(ctx, body, { env: { ...ENV, STRIPE_SECRET_KEY: "" } })).status, 500);
  assert.equal((await checkout(ctx, body, { env: { ...ENV, SITE_URL: "" } })).status, 500);
  assert.equal(
    (await checkout(ctx, body, { env: { ...ENV, SITE_URL: "http://example.com" }, headers: { Origin: "http://example.com" } })).status,
    500,
  );
  assert.equal(
    (await checkout(ctx, body, { env: { ...ENV, STRIPE_CHECKOUT_ORIGIN: "https://checkout.example" } })).status,
    502,
    "session URL must be on the expected Checkout origin",
  );
  const down = await checkout(ctx, body, { fetchImpl: async () => new Response("<html>", { status: 503 }) });
  assert.equal(down.status, 502);
  assert.doesNotMatch(JSON.stringify(await down.json()), /sk_test/);
});

test("live mode requires tax, terms and no endpoint overrides", () => {
  const live = { SITE_URL: SITE, STRIPE_SECRET_KEY: "sk_live_x", STRIPE_AUTOMATIC_TAX: "true", STRIPE_REQUIRE_TERMS: "true" };
  assert.equal(configurationProblem(live), "");
  assert.match(configurationProblem({ ...live, STRIPE_AUTOMATIC_TAX: "" }), /AUTOMATIC_TAX/);
  assert.match(configurationProblem({ ...live, STRIPE_REQUIRE_TERMS: "false" }), /REQUIRE_TERMS/);
  assert.match(configurationProblem({ ...live, STRIPE_API_BASE: "https://x" }), /overrides/);
  assert.equal(configurationProblem({ ...live, STRIPE_SECRET_KEY: "sk_test_x", STRIPE_AUTOMATIC_TAX: "" }), "");
});

function webhookRequest(event, secret = "whsec_unit", header) {
  const body = JSON.stringify(event);
  return new Request(`${SITE}/api/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": header ?? signWebhook(body, secret) },
    body,
  });
}

const completed = {
  id: "evt_1",
  type: "checkout.session.completed",
  livemode: false,
  data: {
    object: {
      mode: "subscription",
      subscription: "sub_123",
      amount_total: 2178000,
      currency: "jpy",
      payment_status: "paid",
      metadata: { kasumi_tier: "business", kasumi_interval: "year" },
      customer_details: {
        name: "Example KK",
        email: "ops@example.com",
        address: { country: "JP" },
        tax_ids: [{ type: "jp_trn", value: "T1234567890123" }],
      },
    },
  },
};
const NOTIFY_ENV = { STRIPE_WEBHOOK_SECRET: "whsec_unit", NOTIFY_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/x" };

test("webhook sends a notice without customer personal data", async () => {
  const sent = [];
  const fetchImpl = async (url, init) => {
    sent.push({ url, init, body: JSON.parse(init.body) });
    return new Response("ok");
  };
  const response = await handleWebhook(webhookRequest(completed), { env: NOTIFY_ENV, fetchImpl });
  assert.equal(response.status, 200);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].init.redirect, "error");
  const message = sent[0].body.text;
  assert.match(message, /^\[TEST\] New Kasumi support subscription: business \(year\)/);
  assert.match(message, /¥2,178,000/);
  assert.match(message, /billing country JP/);
  assert.match(message, /dashboard\.stripe\.com\/test\/subscriptions\/sub_123/);
  assert.doesNotMatch(message, /Example KK|ops@example\.com|T1234567890123/);
});

test("webhook ignores other Stripe products and unrelated events", async () => {
  const ok = async () => assert.fail("must not notify");
  const other = structuredClone(completed);
  delete other.data.object.metadata;
  const r1 = await handleWebhook(webhookRequest(other), { env: NOTIFY_ENV, fetchImpl: ok });
  assert.equal((await r1.json()).ignored, "checkout.session.completed");
  const unrelated = { ...completed, type: "customer.created" };
  assert.equal((await (await handleWebhook(webhookRequest(unrelated), { env: NOTIFY_ENV, fetchImpl: ok })).json()).ignored, "customer.created");
});

test("webhook rejects bad signatures and retries failed or missing notices", async () => {
  const ok = async () => new Response("ok");
  assert.equal((await handleWebhook(webhookRequest(completed, "whsec_wrong"), { env: NOTIFY_ENV, fetchImpl: ok })).status, 400);
  assert.equal((await handleWebhook(webhookRequest(completed, "whsec_unit", "t=1,v1=00"), { env: NOTIFY_ENV, fetchImpl: ok })).status, 400);
  const failing = async () => new Response("no", { status: 500 });
  assert.equal((await handleWebhook(webhookRequest(completed), { env: NOTIFY_ENV, fetchImpl: failing })).status, 500);
  assert.equal((await handleWebhook(webhookRequest(completed), { env: {}, fetchImpl: ok })).status, 500, "no secret");
  const noTarget = { STRIPE_WEBHOOK_SECRET: "whsec_unit" };
  assert.equal((await handleWebhook(webhookRequest(completed), { env: noTarget, fetchImpl: ok })).status, 200, "test mode");
  const live = { ...completed, livemode: true };
  assert.equal((await handleWebhook(webhookRequest(live), { env: noTarget, fetchImpl: ok })).status, 500, "live mode");
  const badHost = { ...NOTIFY_ENV, NOTIFY_WEBHOOK_URL: "https://attacker.example/hook" };
  assert.equal((await handleWebhook(webhookRequest(completed), { env: badHost, fetchImpl: ok })).status, 500);
});

test("notify target allows only https on approved hosts", () => {
  assert.equal(notifyTarget({ NOTIFY_WEBHOOK_URL: "https://hooks.slack.com/x" }).url, "https://hooks.slack.com/x");
  assert.match(notifyTarget({ NOTIFY_WEBHOOK_URL: "http://hooks.slack.com/x" }).error, /https/);
  assert.match(notifyTarget({ NOTIFY_WEBHOOK_URL: "https://example.com/x" }).error, /host/);
  assert.equal(
    notifyTarget({ NOTIFY_WEBHOOK_URL: "https://example.com/x", NOTIFY_WEBHOOK_HOSTS: "example.com" }).url,
    "https://example.com/x",
  );
});

test("webhook recognises Kasumi invoices and subscription changes", () => {
  // Clover-shaped invoice without subscription metadata (e.g. a subscription
  // created in the Dashboard): identified by the line's Product id.
  const invoice = {
    id: "in_1", object: "invoice", amount_due: 40000, currency: "usd",
    parent: { type: "subscription_details", subscription_details: { metadata: {}, subscription: "sub_1" } },
    lines: { data: [{ object: "line_item", metadata: {}, pricing: { type: "price_details", price_details: { price: "price_123", product: "kasumi_support_standard" } } }] },
  };
  assert.equal(kasumiTier(invoice), "standard");
  const foreign = structuredClone(invoice);
  foreign.lines.data[0].pricing.price_details.product = "prod_other";
  assert.equal(kasumiTier(foreign), "", "another Soramitsu product is ignored");
  assert.match(describeEvent({ type: "invoice.payment_failed", livemode: true, data: { object: invoice } }), /payment failed: standard · \$400\.00/);
  const parent = { id: "in_2", amount_paid: 66000, currency: "jpy", billing_reason: "subscription_cycle", parent: { subscription_details: { metadata: { kasumi_tier: "standard" } } } };
  assert.match(describeEvent({ type: "invoice.paid", livemode: true, data: { object: parent } }), /invoice paid \(subscription_cycle\): standard · ¥66,000/);
  const sub = { id: "sub_9", cancel_at_period_end: true, metadata: { kasumi_tier: "business" } };
  assert.match(
    describeEvent({ type: "customer.subscription.updated", livemode: true, data: { object: sub, previous_attributes: { cancel_at_period_end: false } } }),
    /will cancel at period end: business\nhttps:\/\/dashboard\.stripe\.com\/subscriptions\/sub_9$/,
  );
  assert.equal(describeEvent({ type: "customer.subscription.updated", livemode: true, data: { object: sub, previous_attributes: { metadata: {} } } }), null);
  assert.match(describeEvent({ type: "customer.subscription.deleted", livemode: false, data: { object: sub } }), /^\[TEST\] Kasumi support subscription ended: business/);
});

test("the published plans.js is valid for Stripe setup and checkout", async () => {
  const plans = await loadPlans();
  const prices = checkoutPrices(plans);
  for (const p of prices) assert.ok(Number.isSafeInteger(p.unitAmount) && p.unitAmount > 0, p.lookupKey);
  const ids = new Set(plans.tiers.map((t) => t.id));
  assert.equal(ids.size, plans.tiers.length, "tier ids are unique");
  assert.equal(typeof plans.selfServeOpen, "boolean");

  // Every self-serve tier can be bought end to end against a fake Stripe.
  const ctx = await seeded(plans);
  for (const p of prices) {
    const response = await checkout(ctx, { tier: p.tier, interval: p.interval, currency: p.currency });
    assert.equal(response.status, plans.selfServeOpen ? 200 : 403, p.lookupKey);
  }
});

test("the legal notice shows the same prices as plans.js", async () => {
  const html = await readFile(new URL("../public/legal/tokushoho.html", import.meta.url), "utf8");
  const plans = await loadPlans();
  const yen = (n) => "¥" + n.toLocaleString("en-US");
  for (const tier of plans.tiers.filter((t) => t.checkout)) {
    const start = html.indexOf(`<tr data-tier="${tier.id}">`);
    assert.ok(start >= 0, `tokushoho has a row for ${tier.id}`);
    const row = html.slice(start, html.indexOf("</tr>", start));
    for (const interval of ["month", "year"]) {
      const net = tier.price.JPY[interval];
      assert.ok(row.includes(yen(net)), `${tier.id} ${interval} ${yen(net)}`);
      assert.ok(row.includes(yen(Math.round(net * 1.1))), `${tier.id} ${interval} incl. tax`);
      assert.ok(html.includes("$" + tier.price.USD[interval].toLocaleString("en-US")), `${tier.id} USD ${interval}`);
    }
  }
});

test("the versioned terms page Checkout links to matches the current terms", async () => {
  const plans = await loadPlans();
  const main = (html) => html.slice(html.indexOf("<main"), html.indexOf("</main>"));
  const current = await readFile(new URL("../public/legal/support-terms.html", import.meta.url), "utf8");
  const versioned = await readFile(new URL(`../public/legal/support-terms-${plans.termsVersion}.html`, import.meta.url), "utf8");
  assert.equal(main(versioned), main(current), "copy support-terms.html to a new versioned file when the terms change");
  assert.ok(current.includes(`Version ${plans.termsVersion}`), "terms page states its version");
});

test("the prerendered language pages are current and localized", async () => {
  const { prerenderTargets, richHtml } = await import("../scripts/prerender.mjs");
  for (const { path, expected } of await prerenderTargets()) {
    assert.equal(await readFile(path, "utf8"), expected, `${path} is stale: node scripts/prerender.mjs`);
  }
  const ja = await readFile(new URL("../public/ja.html", import.meta.url), "utf8");
  assert.match(ja, /<html lang="ja"/);
  assert.match(ja, /<title data-i18n="meta.title">Kasumi（カスミ）/);
  assert.match(ja, /<link rel="canonical" href="https:\/\/kasumi\.soramitsu\.co\.jp\/ja">/);
  assert.match(ja, /<meta property="og:locale" data-i18n-attr="content:meta.locale" content="ja_JP">/);
  assert.equal(richHtml("a `b<c>` d"), "a <code>b&lt;c&gt;</code> d");
  assert.equal(richHtml("東京の|データベース"), '<span class="ph">東京の</span><span class="ph">データベース</span>');
});

test("secondary pages carry the current header and footer", async () => {
  const chrome = await chromeFromIndex();
  for (const name of PAGES) {
    const page = await readFile(new URL(`../public/${name}`, import.meta.url), "utf8");
    assert.equal(syncPage(page, chrome), page, `${name} is out of date: npm run sync-chrome`);
  }
});
