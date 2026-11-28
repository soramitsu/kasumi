// In-memory stand-in for the parts of the Stripe API the website uses.
// Used by the unit tests and by `npm run dev -- --fake-stripe`, so the whole
// checkout flow can be clicked through without a Stripe account or key.

import { randomUUID } from "node:crypto";

// Parse Stripe-style form keys (a[b][0][c]=v) into nested objects/arrays.
export function formDecode(body) {
  const out = {};
  for (const [key, value] of new URLSearchParams(body || "")) {
    const parts = key.replace(/\]/g, "").split("[");
    let node = out;
    parts.forEach((part, i) => {
      const last = i === parts.length - 1;
      const nextIsIndex = !last && /^\d+$/.test(parts[i + 1]);
      if (last) {
        node[part] = value;
      } else {
        node[part] ??= nextIsIndex ? [] : {};
        node = node[part];
      }
    });
  }
  return out;
}

const bool = (v) => v === true || v === "true";

const CHECKOUT_PARAMS = new Set([
  "mode", "currency", "line_items", "payment_method_types", "adaptive_pricing", "success_url", "cancel_url",
  "locale", "billing_address_collection", "name_collection", "tax_id_collection", "automatic_tax",
  "allow_promotion_codes", "consent_collection", "custom_text", "client_reference_id", "metadata",
  "subscription_data", "customer", "customer_update",
]);

export function fakeStripe({ checkoutOrigin = "https://checkout.stripe.com" } = {}) {
  const products = new Map();
  const prices = new Map();
  const sessions = [];
  const calls = [];

  const respond = (status, body) =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  const missing = (what) => respond(404, { error: { type: "invalid_request_error", code: "resource_missing", message: `No such ${what}` } });

  function withProduct(price, expand) {
    return expand ? { ...price, product: products.get(price.product) || price.product } : price;
  }

  // Stripe replays the first response for a repeated Idempotency-Key and
  // rejects the key if the parameters differ.
  const idempotent = new Map();
  const pending = new Set();
  async function fetchImpl(input, init = {}) {
    const key = (init.method || "GET").toUpperCase() === "POST" ? init.headers?.["Idempotency-Key"] : undefined;
    if (key && idempotent.has(key)) {
      const prior = idempotent.get(key);
      if (prior.body !== init.body) {
        return respond(400, { error: { type: "idempotency_error", message: "Keys for idempotent requests can only be used with the same parameters" } });
      }
      return new Response(prior.text, { status: prior.status, headers: { "Content-Type": "application/json" } });
    }
    if (key && pending.has(key)) {
      return respond(409, { error: { type: "idempotency_error", message: "There is currently another in-progress request using this Idempotent Key" } });
    }
    if (key) pending.add(key);
    try {
      await new Promise((resolve) => setTimeout(resolve, 5)); // let a concurrent duplicate arrive
      const response = await handle(input, init);
      if (key) idempotent.set(key, { body: init.body, status: response.status, text: await response.clone().text() });
      return response;
    } finally {
      if (key) pending.delete(key);
    }
  }

  async function handle(input, init) {
    const url = new URL(String(input));
    const method = (init.method || "GET").toUpperCase();
    const params = method === "GET" ? formDecode(url.search.slice(1)) : formDecode(init.body);
    const path = url.pathname;
    calls.push({ method, path, params, headers: init.headers || {} });
    if (!String(init.headers?.Authorization || "").startsWith("Bearer ")) {
      return respond(401, { error: { type: "invalid_request_error", message: "No API key provided" } });
    }

    let m;
    if (method === "GET" && path === "/v1/products") {
      const all = [...products.values()];
      const start = params.starting_after ? all.findIndex((p) => p.id === params.starting_after) + 1 : 0;
      const limit = Number(params.limit || 10);
      return respond(200, { object: "list", data: all.slice(start, start + limit), has_more: start + limit < all.length });
    }
    if ((m = path.match(/^\/v1\/products\/([^/]+)$/))) {
      const product = products.get(m[1]);
      if (!product) return missing("product");
      if (method === "GET") return respond(200, product);
      if (params.active !== undefined) product.active = bool(params.active);
      for (const k of ["name", "description", "tax_code"]) if (params[k] !== undefined) product[k] = params[k];
      if (params.metadata) product.metadata = { ...product.metadata, ...params.metadata };
      return respond(200, product);
    }
    if (method === "POST" && path === "/v1/products") {
      const id = params.id || `prod_${randomUUID().slice(0, 8)}`;
      const product = {
        id, object: "product", active: true, name: params.name, description: params.description || null,
        metadata: params.metadata || {}, tax_code: params.tax_code || null,
      };
      products.set(id, product);
      return respond(200, product);
    }
    if (method === "GET" && path === "/v1/prices") {
      const keys = params.lookup_keys;
      const expand = (params.expand || []).includes("data.product");
      let list = [...prices.values()];
      if (keys) list = list.filter((p) => keys.includes(p.lookup_key));
      if (params.product) list = list.filter((p) => p.product === params.product);
      if (params.active !== undefined) list = list.filter((p) => p.active === bool(params.active));
      const start = params.starting_after ? list.findIndex((p) => p.id === params.starting_after) + 1 : 0;
      const limit = Number(params.limit || 10);
      return respond(200, {
        object: "list",
        data: list.slice(start, start + limit).map((p) => withProduct(p, expand)),
        has_more: start + limit < list.length,
      });
    }
    if (method === "POST" && path === "/v1/prices") {
      if (!products.has(params.product)) return missing("product");
      if (params.lookup_key) {
        for (const p of prices.values()) {
          if (p.lookup_key === params.lookup_key) {
            if (!bool(params.transfer_lookup_key)) {
              return respond(400, { error: { type: "invalid_request_error", message: "lookup_key already in use" } });
            }
            p.lookup_key = null;
          }
        }
      }
      const id = `price_${randomUUID().slice(0, 8)}`;
      const price = {
        id, object: "price", active: true, type: "recurring", product: params.product,
        currency: params.currency, unit_amount: Number(params.unit_amount),
        billing_scheme: params.billing_scheme || "per_unit", transform_quantity: null,
        recurring: { interval: params.recurring?.interval, interval_count: 1, usage_type: params.recurring?.usage_type || "licensed" },
        lookup_key: params.lookup_key || null, tax_behavior: params.tax_behavior || "unspecified",
        nickname: params.nickname || null, metadata: params.metadata || {},
      };
      prices.set(id, price);
      return respond(200, price);
    }
    if ((m = path.match(/^\/v1\/prices\/([^/]+)$/)) && method === "POST") {
      const price = prices.get(m[1]);
      if (!price) return missing("price");
      if (params.active !== undefined) price.active = bool(params.active);
      return respond(200, price);
    }
    if (method === "POST" && path === "/v1/checkout/sessions") {
      // Parameters checked against the API reference for 2026-02-25.clover.
      const unknown = Object.keys(params).filter((k) => !CHECKOUT_PARAMS.has(k));
      if (unknown.length) return respond(400, { error: { type: "invalid_request_error", message: `Received unknown parameter: ${unknown[0]}` } });
      const price = prices.get(params.line_items?.[0]?.price);
      if (!price || !price.active) return missing("price");
      if (params.mode === "subscription" && price.type !== "recurring") {
        return respond(400, { error: { type: "invalid_request_error", message: "subscription mode needs a recurring price" } });
      }
      const id = `cs_test_${randomUUID().replace(/-/g, "")}`;
      const session = { id, object: "checkout.session", url: `${checkoutOrigin}/c/pay/${id}`, params };
      sessions.push(session);
      return respond(200, session);
    }
    return respond(404, { error: { type: "invalid_request_error", message: `Unrecognized request URL (${method} ${path})` } });
  }

  return { fetchImpl, products, prices, sessions, calls };
}
