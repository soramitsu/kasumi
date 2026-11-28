// POST /api/checkout — create a Stripe Checkout Session for a support plan.
//
// The browser sends {tier, interval, currency, locale, attempt, revision}.
// The tier must be a self-serve tier in public/assets/plans.js while
// selfServeOpen is true, the revision must be the catalog revision the page
// was rendered from, and the Stripe Price found by lookup key must match the
// catalog entry exactly (product, amount, currency, interval, licensed
// per-unit billing, tax behaviour). Amounts never come from the browser.

import { stripeClient, StripeError } from "./stripe.js";
import { json, readBody } from "./http.js";
import { CURRENCIES, INTERVALS, LOCALES, TIER_ID, loadPlans, lookupKey, productId, toMinorUnits } from "./plans.js";

const MAX_BODY_BYTES = 1024;
const ATTEMPT_ID = /^[A-Za-z0-9-]{16,64}$/;
const REVISION = /^[A-Za-z0-9._-]{1,40}$/;

export function siteOrigin(env) {
  const raw = env.SITE_URL;
  if (!raw) throw new StripeError("SITE_URL is not set", { status: 500, type: "configuration" });
  const url = new URL(raw);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost"].includes(url.hostname))) {
    throw new StripeError("SITE_URL must be https", { status: 500, type: "configuration" });
  }
  return url.origin;
}

export function isLiveKey(key) {
  return /^(sk|rk)_live_/.test(key || "");
}

// Live mode never sells without tax calculation and the terms checkbox, and
// never sends a live key anywhere but api.stripe.com.
export function configurationProblem(env) {
  if (!env.STRIPE_SECRET_KEY) return "STRIPE_SECRET_KEY is not set";
  if (isLiveKey(env.STRIPE_SECRET_KEY)) {
    if (env.STRIPE_AUTOMATIC_TAX !== "true") return "live mode requires STRIPE_AUTOMATIC_TAX=true";
    if (env.STRIPE_REQUIRE_TERMS !== "true") return "live mode requires STRIPE_REQUIRE_TERMS=true";
    if (env.STRIPE_API_BASE || env.STRIPE_CHECKOUT_ORIGIN) return "live mode refuses Stripe endpoint overrides";
    if (!env.SITE_URL?.startsWith("https://")) return "live mode requires an https SITE_URL";
  }
  return "";
}

export function parseCheckoutBody(raw) {
  if (raw === null || Buffer.byteLength(raw, "utf8") > MAX_BODY_BYTES) return { error: "Request too large.", status: 413 };
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return { error: "Request body must be JSON." };
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return { error: "Request body must be an object." };
  const tier = typeof body.tier === "string" ? body.tier : "";
  const interval = typeof body.interval === "string" ? body.interval : "";
  const currency = typeof body.currency === "string" ? body.currency.toLowerCase() : "";
  const locale = typeof body.locale === "string" && LOCALES.includes(body.locale) ? body.locale : "en";
  const attempt = typeof body.attempt === "string" && ATTEMPT_ID.test(body.attempt) ? body.attempt : "";
  const revision = typeof body.revision === "string" && REVISION.test(body.revision) ? body.revision : "";
  if (!TIER_ID.test(tier)) return { error: "Unknown plan." };
  if (!INTERVALS.includes(interval)) return { error: "Unknown billing interval." };
  if (!CURRENCIES.includes(currency)) return { error: "Unsupported currency." };
  return { tier, interval, currency, locale, attempt, revision };
}

// The catalog entry the request names, or null when it is not sold online.
export function catalogEntry(plans, { tier, interval, currency }) {
  if (!plans.selfServeOpen) return null;
  if (!(plans.currencies || []).map((c) => c.toLowerCase()).includes(currency)) return null;
  if (!(plans.intervals || []).includes(interval)) return null;
  const plan = plans.tiers.find((t) => t.id === tier);
  if (!plan || !plan.checkout) return null;
  const amount = plan.price?.[currency.toUpperCase()]?.[interval];
  if (amount === undefined) return null;
  return { plan, unitAmount: toMinorUnits(amount, currency) };
}

// A flat, licensed, per-unit recurring Price: quantity 1 is charged exactly
// unit_amount per interval. Shared with scripts/stripe-setup.mjs.
export function isSimpleRecurring(price, { interval, currency, unitAmount }) {
  return Boolean(
    price &&
      price.type === "recurring" &&
      price.billing_scheme === "per_unit" &&
      !price.transform_quantity &&
      price.recurring?.interval === interval &&
      (price.recurring?.interval_count ?? 1) === 1 &&
      price.recurring?.usage_type === "licensed" &&
      price.currency === currency &&
      price.unit_amount === unitAmount &&
      price.tax_behavior === "exclusive",
  );
}

// Check that the Price found by lookup key is exactly the catalog entry.
export function priceMatches(price, { tier, interval, currency, unitAmount }) {
  const product = price && typeof price.product === "object" ? price.product : null;
  return Boolean(
    price &&
      price.active &&
      isSimpleRecurring(price, { interval, currency, unitAmount }) &&
      price.lookup_key === lookupKey(tier, interval, currency) &&
      price.metadata?.kasumi_tier === tier &&
      product &&
      product.id === productId(tier) &&
      product.active &&
      product.metadata?.kasumi_tier === tier &&
      product.metadata?.kasumi_checkout === "true",
  );
}

const SUBMIT_TEXT = {
  ja: {
    month: "月額のサポート契約です。本日初回分を決済し、以後毎月自動更新します。請求ポータルまたは service@soramitsu.co.jp へのメールでいつでも解約でき、解約後も当期末まで利用できます。",
    year: "年額一括払いのサポート契約です。本日1年分を決済し、以後毎年自動更新します。請求ポータルまたは service@soramitsu.co.jp へのメールでいつでも解約でき、解約後も当期末まで利用できます。",
  },
  en: {
    month: "Monthly support subscription. You are charged today and then every month until you cancel in the billing portal or by email to service@soramitsu.co.jp; support continues to the end of the paid period.",
    year: "Annual support subscription, paid upfront. You are charged for a full year today and then every year until you cancel in the billing portal or by email to service@soramitsu.co.jp; support continues to the end of the paid period.",
  },
};

export function termsUrl(origin, termsVersion) {
  return termsVersion ? `${origin}/legal/support-terms-${termsVersion}` : `${origin}/legal/support-terms`;
}

export function sessionParams({ price, tier, interval, currency, locale, attempt, origin, env, termsVersion }) {
  const lang = locale === "ja" ? "ja" : "en";
  const requireTerms = env.STRIPE_REQUIRE_TERMS === "true";
  const terms = termsUrl(origin, termsVersion);
  const metadata = { kasumi_tier: tier, kasumi_interval: interval, kasumi_currency: currency };
  if (termsVersion) metadata.kasumi_terms = termsVersion;
  if (attempt) metadata.kasumi_attempt = attempt;
  const selection = new URLSearchParams({ interval, currency: currency.toUpperCase() });
  return {
    mode: "subscription",
    currency,
    line_items: [{ price: price.id, quantity: 1 }],
    payment_method_types: ["card"],
    adaptive_pricing: { enabled: false },
    success_url: `${origin}/thanks?lang=${lang}`,
    cancel_url: `${origin}/${lang}?${selection}#support`,
    locale: lang,
    billing_address_collection: "required",
    name_collection: { business: { enabled: true, optional: false } },
    tax_id_collection: { enabled: true },
    automatic_tax: { enabled: env.STRIPE_AUTOMATIC_TAX === "true" },
    allow_promotion_codes: env.STRIPE_ALLOW_PROMOTION_CODES === "true" ? true : undefined,
    consent_collection: requireTerms ? { terms_of_service: "required" } : undefined,
    custom_text: {
      terms_of_service_acceptance: requireTerms
        ? {
            message:
              lang === "ja"
                ? `事業目的で申し込み、[Kasumi サポート利用規約](${terms})に同意します。`
                : `I am buying for a business and agree to the [Kasumi Support Terms](${terms}).`,
          }
        : undefined,
      submit: { message: SUBMIT_TEXT[lang][interval] },
    },
    client_reference_id: attempt || undefined,
    metadata,
    subscription_data: { metadata },
  };
}

export async function handleCheckout(request, { env = process.env, fetchImpl, plans } = {}) {
  if (request.method !== "POST") return json(405, { error: "Method not allowed." });

  let origin;
  try {
    origin = siteOrigin(env);
  } catch (err) {
    console.error("checkout configuration:", err.message);
    return json(500, { error: "Checkout is not configured." });
  }

  // Browsers always send Origin on a POST fetch. Requests without it carry no
  // ambient credentials (the endpoint uses none), so they are not refused.
  const requestOrigin = request.headers.get("origin");
  if (requestOrigin && requestOrigin !== origin) return json(403, { error: "Origin not allowed." });

  const type = request.headers.get("content-type") || "";
  if (!type.toLowerCase().startsWith("application/json")) return json(415, { error: "Use application/json." });

  const parsed = parseCheckoutBody(await readBody(request, MAX_BODY_BYTES));
  if (parsed.error) return json(parsed.status || 400, { error: parsed.error });
  const { tier, interval, currency, locale, attempt, revision } = parsed;

  let catalog;
  try {
    catalog = plans || (await loadPlans());
  } catch (err) {
    console.error("checkout catalog:", err.message);
    return json(500, { error: "Checkout is not configured." });
  }
  if (!catalog.selfServeOpen) return json(403, { error: "Online subscriptions are not open." });
  if (catalog.revision && revision !== catalog.revision) {
    return json(409, { error: "Plans or prices have changed. Reload the page.", code: "stale_catalog" });
  }
  const entry = catalogEntry(catalog, { tier, interval, currency });
  if (!entry) return json(404, { error: "This plan is not available for online checkout." });

  const problem = configurationProblem(env);
  if (problem) {
    console.error("checkout configuration:", problem);
    return json(500, { error: "Checkout is not configured." });
  }
  const stripe = stripeClient({
    secretKey: env.STRIPE_SECRET_KEY,
    apiVersion: env.STRIPE_API_VERSION || undefined,
    apiBase: env.STRIPE_API_BASE || undefined,
    fetchImpl,
  });

  try {
    const key = lookupKey(tier, interval, currency);
    const prices = await stripe.get("/v1/prices", {
      lookup_keys: [key],
      active: "true",
      expand: ["data.product"],
      limit: 1,
    });
    const price = prices.data?.[0];
    if (!priceMatches(price, { tier, interval, currency, unitAmount: entry.unitAmount })) {
      console.error(`checkout: Stripe price for ${key} does not match plans.js; run scripts/stripe-setup.mjs`);
      return json(404, { error: "This plan is not available for online checkout." });
    }

    // A double click or client retry with the same attempt id gets the same
    // Session back from Stripe instead of a second payable one.
    const idempotencyKey = attempt ? `kasumi-checkout-${attempt}-${tier}-${interval}-${currency}-${locale}` : undefined;
    const session = await stripe.post(
      "/v1/checkout/sessions",
      sessionParams({ price, tier, interval, currency, locale, attempt, origin, env, termsVersion: catalog.termsVersion }),
      { idempotencyKey },
    );
    const allowed = env.STRIPE_CHECKOUT_ORIGIN || "https://checkout.stripe.com";
    if (typeof session.url !== "string" || new URL(session.url).origin !== allowed) {
      console.error("checkout: unexpected session url origin");
      return json(502, { error: "Payment provider returned an unexpected response." });
    }
    return json(200, { url: session.url });
  } catch (err) {
    console.error("checkout stripe error:", err.status, err.type, err.code, err.message);
    return json(502, { error: "Could not start checkout. Please try again or contact us." });
  }
}
