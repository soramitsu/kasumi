#!/usr/bin/env node
// Create or update the Stripe Products and Prices for Kasumi support plans.
//
// Reads public/assets/plans.js (the same file the page renders), so the page
// and Stripe never disagree about amounts. Dry run by default.
//
//   STRIPE_SECRET_KEY=sk_test_... node scripts/stripe-setup.mjs           # show the plan
//   STRIPE_SECRET_KEY=sk_test_... node scripts/stripe-setup.mjs --apply   # make the changes
//   STRIPE_SECRET_KEY=sk_live_... node scripts/stripe-setup.mjs --apply --live
//
// Prices are immutable in Stripe. When an amount changes, the script creates a
// new Price, moves the lookup key to it (transfer_lookup_key) and archives the
// old one; existing subscriptions keep their old Price until changed in Stripe.

import { pathToFileURL } from "node:url";
import { stripeClient, StripeError } from "../lib/stripe.js";
import { LOOKUP_PREFIX, checkoutPrices, loadPlans, productId, text } from "../lib/plans.js";
import { isSimpleRecurring } from "../lib/checkout.js";

export async function planChanges(stripe, plans, { taxCode = plans.stripeTaxCode } = {}) {
  const wanted = checkoutPrices(plans);
  const actions = [];
  const tiers = new Map();
  for (const price of wanted) {
    if (!tiers.has(price.tier)) tiers.set(price.tier, price);
  }

  // Products: one per checkout tier, with a deterministic id.
  for (const [tier, sample] of tiers) {
    const id = productId(tier);
    const desired = {
      name: `Kasumi ${sample.tierName} Support`,
      description: sample.summary || undefined,
      metadata: { kasumi_tier: tier, kasumi_checkout: "true" },
      tax_code: taxCode || undefined,
    };
    let existing = null;
    try {
      existing = await stripe.get(`/v1/products/${id}`);
    } catch (err) {
      if (!(err instanceof StripeError) || err.status !== 404) throw err;
    }
    if (!existing) {
      actions.push({ kind: "create-product", id, params: { id, ...desired } });
    } else if (
      !existing.active ||
      existing.name !== desired.name ||
      (existing.description || undefined) !== desired.description ||
      existing.metadata?.kasumi_checkout !== "true" ||
      existing.metadata?.kasumi_tier !== tier ||
      (taxCode && existing.tax_code !== taxCode)
    ) {
      actions.push({ kind: "update-product", id, params: { active: true, ...desired } });
    }
  }

  // Prices: one per tier × currency × interval, addressed by lookup key.
  const keep = new Set();
  const archiving = new Set();
  for (const price of wanted) {
    const found = await stripe.get("/v1/prices", { lookup_keys: [price.lookupKey], limit: 1 });
    const current = found.data?.[0];
    const same =
      current &&
      current.active &&
      isSimpleRecurring(current, price) &&
      (typeof current.product === "string" ? current.product : current.product?.id) === productId(price.tier) &&
      current.metadata?.kasumi_tier === price.tier;
    if (same) {
      keep.add(current.id);
      continue;
    }
    actions.push({
      kind: "create-price",
      lookupKey: price.lookupKey,
      replaces: current?.id || null,
      params: {
        product: productId(price.tier),
        currency: price.currency,
        unit_amount: price.unitAmount,
        billing_scheme: "per_unit",
        recurring: { interval: price.interval, usage_type: "licensed" },
        tax_behavior: "exclusive",
        lookup_key: price.lookupKey,
        transfer_lookup_key: true,
        nickname: `${price.tierName} ${price.interval}ly ${price.currency.toUpperCase()}`,
        metadata: { kasumi_tier: price.tier, kasumi_interval: price.interval, kasumi_currency: price.currency },
      },
    });
    if (current?.active) {
      actions.push({ kind: "archive-price", id: current.id, lookupKey: price.lookupKey });
      archiving.add(current.id);
    }
  }

  // Any other active Price on a sold product is a leftover (an interrupted
  // run that moved a lookup key but did not archive, or a removed currency or
  // interval): archive it so only the lookup-key holders stay sellable.
  // Existing subscriptions keep working on archived Prices.
  for (const tier of tiers.keys()) {
    let active = [];
    try {
      active = await listAll(stripe, "/v1/prices", { product: productId(tier), active: "true" });
    } catch (err) {
      if (!(err instanceof StripeError) || err.status !== 404) throw err;
    }
    for (const p of active) {
      if (keep.has(p.id) || archiving.has(p.id)) continue;
      actions.push({ kind: "archive-price", id: p.id, lookupKey: p.lookup_key || "(none)" });
      archiving.add(p.id);
    }
  }

  // Tiers that left self-serve checkout: stop the checkout function using them.
  for (const product of await listAll(stripe, "/v1/products")) {
    if (!product.id.startsWith(LOOKUP_PREFIX)) continue;
    const tier = product.metadata?.kasumi_tier;
    if (tiers.has(tier) || product.metadata?.kasumi_checkout !== "true") continue;
    actions.push({ kind: "retire-product", id: product.id, params: { metadata: { kasumi_checkout: "false" } } });
  }
  return actions;
}

async function listAll(stripe, path, params = {}) {
  const out = [];
  let startingAfter;
  for (;;) {
    const page = await stripe.get(path, { ...params, limit: 100, starting_after: startingAfter });
    out.push(...(page.data || []));
    if (!page.has_more || !page.data?.length) return out;
    startingAfter = page.data.at(-1).id;
  }
}

export async function applyChanges(stripe, actions, log = console.log) {
  for (const action of actions) {
    switch (action.kind) {
      case "create-product":
        await stripe.post("/v1/products", action.params, { idempotencyKey: `kasumi-setup-${action.id}` });
        break;
      case "update-product":
      case "retire-product":
        await stripe.post(`/v1/products/${action.id}`, action.params);
        break;
      case "create-price":
        await stripe.post("/v1/prices", action.params);
        break;
      case "archive-price":
        await stripe.post(`/v1/prices/${action.id}`, { active: false });
        break;
      default:
        throw new Error(`unknown action ${action.kind}`);
    }
    log(`  done: ${describe(action)}`);
  }
}

export function describe(action) {
  switch (action.kind) {
    case "create-product":
    case "update-product":
      return `${action.kind} ${action.id} "${action.params.name}"`;
    case "retire-product":
      return `retire-product ${action.id} (no longer sold online)`;
    case "create-price": {
      const p = action.params;
      return `create-price ${action.lookupKey} = ${p.unit_amount} ${p.currency}/${p.recurring.interval}${action.replaces ? ` (replaces ${action.replaces})` : ""}`;
    }
    case "archive-price":
      return `archive-price ${action.id} (${action.lookupKey})`;
    default:
      return action.kind;
  }
}

async function main(argv) {
  const apply = argv.includes("--apply");
  const live = argv.includes("--live");
  const taxCodeArg = argv.find((a) => a.startsWith("--tax-code="));
  const taxCode = taxCodeArg ? taxCodeArg.slice("--tax-code=".length) : process.env.STRIPE_TAX_CODE || undefined;
  const key = process.env.STRIPE_SECRET_KEY || "";
  const mode = /^(sk|rk)_live_/.test(key) ? "live" : /^(sk|rk)_test_/.test(key) ? "test" : "unknown";

  if (!key) throw new Error("Set STRIPE_SECRET_KEY (a test-mode key first).");
  if (mode === "unknown" && !process.env.STRIPE_API_BASE) throw new Error("STRIPE_SECRET_KEY is not a Stripe secret or restricted key.");
  if (mode === "live" && !live) throw new Error("This is a live-mode key. Re-run with --live to change live Products and Prices.");
  if (mode === "live" && process.env.STRIPE_API_BASE) throw new Error("Refusing to send a live-mode key to STRIPE_API_BASE; unset it.");

  const plans = await loadPlans();
  const stripe = stripeClient();
  console.log(`Stripe ${mode} mode. Plans: ${plans.tiers.map((t) => `${t.id}${t.checkout ? "" : " (contact)"}`).join(", ")}`);
  const actions = await planChanges(stripe, plans, taxCode ? { taxCode } : {});
  console.log(`Product tax code: ${taxCode || plans.stripeTaxCode || "account default"} (confirm with Soramitsu's tax adviser).`);
  if (actions.length === 0) {
    console.log("Stripe already matches public/assets/plans.js.");
    return;
  }
  for (const action of actions) console.log(`  ${apply ? "will" : "would"}: ${describe(action)}`);
  if (!apply) {
    console.log("Dry run. Re-run with --apply to make these changes.");
    return;
  }
  await applyChanges(stripe, actions);
  console.log(`Applied ${actions.length} change(s). Contact tiers: ${plans.tiers.filter((t) => !t.checkout).map((t) => text(t.name)).join(", ") || "none"}.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(`stripe-setup: ${err.message}`);
    process.exit(1);
  });
}
