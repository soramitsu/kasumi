// Shared plan naming for the checkout function and the Stripe setup script.
//
// public/assets/plans.js is the single source of plan data. The browser reads
// it as window.KASUMI_PLANS; the setup script evaluates the same file in a
// sandbox. The checkout function never reads amounts from it: it resolves a
// Stripe Price by lookup key and checks that Price against the request.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

export const INTERVALS = ["month", "year"];
export const CURRENCIES = ["jpy", "usd"];
export const LOCALES = ["en", "ja"];
export const TIER_ID = /^[a-z][a-z0-9-]{0,31}$/;
export const LOOKUP_PREFIX = "kasumi_support_";

// Currencies whose Stripe amounts are in whole units rather than cents.
const ZERO_DECIMAL = new Set(["jpy", "krw", "vnd", "clp", "pyg", "xof", "xaf"]);

export function lookupKey(tier, interval, currency) {
  return `${LOOKUP_PREFIX}${tier}_${interval}_${currency.toLowerCase()}`;
}

export function productId(tier) {
  return `${LOOKUP_PREFIX}${tier}`;
}

export function toMinorUnits(amount, currency) {
  const cur = currency.toLowerCase();
  const minor = ZERO_DECIMAL.has(cur) ? amount : Math.round(amount * 100);
  if (!Number.isSafeInteger(minor) || minor <= 0) {
    throw new Error(`invalid ${currency} amount ${amount}`);
  }
  return minor;
}

export function formatMinor(amount, currency) {
  const cur = String(currency || "").toLowerCase();
  const major = ZERO_DECIMAL.has(cur) ? amount : amount / 100;
  try {
    return new Intl.NumberFormat("en-US", { style: "currency", currency: cur.toUpperCase() }).format(major);
  } catch {
    return `${major} ${cur.toUpperCase()}`;
  }
}

export function text(value, lang = "en") {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  return value[lang] || value.en || "";
}

export const PLANS_PATH = fileURLToPath(new URL("../public/assets/plans.js", import.meta.url));

// Evaluate public/assets/plans.js the way a browser would, without a DOM.
export async function loadPlans(path = PLANS_PATH) {
  const source = await readFile(path, "utf8");
  const sandbox = { window: {} };
  vm.runInNewContext(source, sandbox, { filename: path, timeout: 1000 });
  const plans = sandbox.window.KASUMI_PLANS;
  if (!plans || !Array.isArray(plans.tiers)) throw new Error(`${path} did not define window.KASUMI_PLANS.tiers`);
  return plans;
}

// The tiers Stripe should sell, with amounts in minor units per lookup key.
export function checkoutPrices(plans) {
  const currencies = (plans.currencies || []).map((c) => c.toLowerCase());
  const intervals = plans.intervals || [];
  const out = [];
  for (const tier of plans.tiers) {
    if (!tier.checkout) continue;
    if (!TIER_ID.test(tier.id)) throw new Error(`tier id ${JSON.stringify(tier.id)} must match ${TIER_ID}`);
    if (!tier.price) throw new Error(`checkout tier ${tier.id} has no price`);
    for (const currency of currencies) {
      if (!CURRENCIES.includes(currency)) throw new Error(`unsupported currency ${currency}`);
      for (const interval of intervals) {
        if (!INTERVALS.includes(interval)) throw new Error(`unsupported interval ${interval}`);
        const amount = tier.price?.[currency.toUpperCase()]?.[interval];
        if (amount === undefined) throw new Error(`tier ${tier.id} lacks ${currency} ${interval} price`);
        out.push({
          tier: tier.id,
          tierName: text(tier.name),
          summary: text(tier.summary),
          currency,
          interval,
          unitAmount: toMinorUnits(amount, currency),
          lookupKey: lookupKey(tier.id, interval, currency),
        });
      }
    }
  }
  return out;
}
