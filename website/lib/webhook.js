// POST /api/webhook — receive Stripe events and tell Soramitsu about them.
//
// Stripe is the system of record: support staff activate, renew or close a
// customer's support after checking the subscription in the Dashboard. This
// endpoint only sends a notice, so it keeps no state; a duplicate notice
// (Stripe retries) is harmless, a lost one is not, so a failed delivery
// returns 500 and Stripe retries.
//
// Only events that belong to Kasumi support (identified by the kasumi_tier
// metadata the checkout function sets, or a kasumi_support_ price lookup key)
// produce a notice. Notices carry no customer name, email or tax ID: just the
// event, plan, amount, country and a Dashboard link.

import { verifyWebhook } from "./stripe.js";
import { json, readBody } from "./http.js";
import { LOOKUP_PREFIX, formatMinor } from "./plans.js";

const MAX_BODY_BYTES = 256 * 1024;

function dashboard(livemode, path) {
  return `https://dashboard.stripe.com/${livemode ? "" : "test/"}${path}`;
}

// Stripe ids, metadata codes and country codes: letters, digits, _ and -.
function code(value) {
  return String(value ?? "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 100);
}

// The kasumi_tier of a Stripe object, or "" when it is not Kasumi support.
export function kasumiTier(object) {
  const direct = object?.metadata?.kasumi_tier;
  if (direct) return code(direct);
  const fromParent = object?.parent?.subscription_details?.metadata?.kasumi_tier; // invoices, 2025+ API
  if (fromParent) return code(fromParent);
  const legacy = object?.subscription_details?.metadata?.kasumi_tier; // invoices, older API versions
  if (legacy) return code(legacy);
  // Lines of invoices and subscriptions without our metadata (imported or
  // edited in the Dashboard): the Product id is kasumi_support_<tier>, and it
  // survives lookup-key transfers. Clover invoice lines carry it under
  // pricing.price_details.product; subscription items under price.product.
  for (const line of object?.lines?.data || object?.items?.data || []) {
    const metaTier = line?.metadata?.kasumi_tier || line?.price?.metadata?.kasumi_tier;
    if (metaTier) return code(metaTier);
    const product = line?.pricing?.price_details?.product ?? line?.price?.product;
    const id = typeof product === "string" ? product : product?.id;
    if (typeof id === "string" && id.startsWith(LOOKUP_PREFIX)) return code(id.slice(LOOKUP_PREFIX.length));
  }
  return "";
}

export function describeEvent(event) {
  const object = event?.data?.object || {};
  const tier = kasumiTier(object);
  if (!tier) return null;
  const test = event.livemode ? "" : "[TEST] ";
  const link = (path) => dashboard(event.livemode, path);
  switch (event.type) {
    case "checkout.session.completed": {
      if (object.mode !== "subscription") return null;
      const lines = [
        `${test}New Kasumi support subscription: ${tier} (${code(object.metadata?.kasumi_interval)})`,
        `Total ${formatMinor(object.amount_total ?? 0, object.currency)} · billing country ${code(object.customer_details?.address?.country) || "?"} · payment ${code(object.payment_status)}`,
        "Activate support after checking the subscription and its paid invoice:",
      ];
      if (object.subscription) lines.push(link(`subscriptions/${code(object.subscription)}`));
      return lines.join("\n");
    }
    case "invoice.paid":
      return [
        `${test}Kasumi support invoice paid (${code(object.billing_reason) || "invoice"}): ${tier} · ${formatMinor(object.amount_paid ?? 0, object.currency)}`,
        link(`invoices/${code(object.id)}`),
      ].join("\n");
    case "invoice.payment_failed":
    case "invoice.payment_action_required":
      return [
        `${test}Kasumi support payment ${event.type === "invoice.payment_failed" ? "failed" : "needs customer action"}: ${tier} · ${formatMinor(object.amount_due ?? 0, object.currency)}`,
        link(`invoices/${code(object.id)}`),
      ].join("\n");
    case "customer.subscription.updated": {
      const previous = event.data?.previous_attributes || {};
      if (!("cancel_at_period_end" in previous) && !("status" in previous)) return null;
      const state = object.cancel_at_period_end ? "will cancel at period end" : `status ${code(object.status)}`;
      return [`${test}Kasumi support subscription ${state}: ${tier}`, link(`subscriptions/${code(object.id)}`)].join("\n");
    }
    case "customer.subscription.deleted":
      return [`${test}Kasumi support subscription ended: ${tier}`, link(`subscriptions/${code(object.id)}`)].join("\n");
    default:
      return null;
  }
}

export function notifyTarget(env) {
  const raw = env.NOTIFY_WEBHOOK_URL || "";
  if (!raw) return { url: "" };
  let url;
  try {
    url = new URL(raw);
  } catch {
    return { error: "NOTIFY_WEBHOOK_URL is not a URL" };
  }
  const hosts = (env.NOTIFY_WEBHOOK_HOSTS || "hooks.slack.com")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  if (url.protocol !== "https:") return { error: "NOTIFY_WEBHOOK_URL must be https" };
  if (!hosts.includes(url.hostname.toLowerCase())) {
    return { error: `NOTIFY_WEBHOOK_URL host must be one of ${hosts.join(", ")}` };
  }
  return { url: url.href };
}

export async function handleWebhook(request, { env = process.env, fetchImpl = globalThis.fetch } = {}) {
  if (request.method !== "POST") return json(405, { error: "Method not allowed." });
  const raw = await readBody(request, MAX_BODY_BYTES);
  if (raw === null) return json(413, { error: "Too large." });
  let event;
  try {
    event = verifyWebhook(raw, request.headers.get("stripe-signature"), env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("webhook rejected:", err.message);
    return json(err.status === 500 ? 500 : 400, { error: "Invalid webhook." });
  }

  const message = describeEvent(event);
  if (!message) return json(200, { received: true, ignored: event.type });

  const target = notifyTarget(env);
  if (target.error) {
    console.error(`webhook ${event.id}: ${target.error}`);
    return json(500, { error: "Notification target misconfigured." });
  }
  if (!target.url) {
    // In live mode a notice with nowhere to go is an outage: fail so the
    // Stripe Dashboard shows failing deliveries and retries them.
    console.error(`webhook ${event.id} ${event.type}: NOTIFY_WEBHOOK_URL is not set`);
    return event.livemode
      ? json(500, { error: "No notification target." })
      : json(200, { received: true, notified: false });
  }

  try {
    const response = await fetchImpl(target.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: message }),
      redirect: "error",
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
  } catch (err) {
    console.error(`webhook ${event.id}: notification failed:`, err.message);
    return json(500, { error: "Notification failed; Stripe will retry." });
  }
  return json(200, { received: true, notified: true });
}
