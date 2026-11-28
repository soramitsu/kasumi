// Minimal Stripe REST client for the Kasumi website functions.
//
// No npm dependencies: requests go through fetch with form encoding, and
// webhook signatures are checked with node:crypto. The secret key, webhook
// secret and API version come from the environment only.

import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";

// Checkout uses name_collection and adaptive_pricing, which need a 2025+ version.
// Validate a new pin in a Stripe sandbox before changing it.
export const DEFAULT_API_VERSION = "2026-02-25.clover";

export class StripeError extends Error {
  constructor(message, { status = 0, type = "", code = "" } = {}) {
    super(message);
    this.name = "StripeError";
    this.status = status;
    this.type = type;
    this.code = code;
  }
}

// Stripe's form encoding: nested objects become a[b][c]=v, arrays a[0]=v.
export function formEncode(params, prefix = "", out = new URLSearchParams()) {
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    const name = prefix ? `${prefix}[${key}]` : key;
    if (Array.isArray(value)) {
      value.forEach((item, index) => {
        if (item !== null && typeof item === "object") {
          formEncode(item, `${name}[${index}]`, out);
        } else {
          out.append(`${name}[${index}]`, String(item));
        }
      });
    } else if (typeof value === "object") {
      formEncode(value, name, out);
    } else {
      out.append(name, String(value));
    }
  }
  return out;
}

export function stripeClient({
  secretKey = process.env.STRIPE_SECRET_KEY,
  apiVersion = process.env.STRIPE_API_VERSION || DEFAULT_API_VERSION,
  apiBase = process.env.STRIPE_API_BASE || "https://api.stripe.com",
  fetchImpl = globalThis.fetch,
  timeoutMs = 5000,
} = {}) {
  if (!secretKey) {
    throw new StripeError("STRIPE_SECRET_KEY is not set", { status: 500, type: "configuration" });
  }

  async function request(method, path, params, { idempotencyKey } = {}) {
    const headers = {
      Authorization: `Bearer ${secretKey}`,
      "Stripe-Version": apiVersion,
    };
    let url = `${apiBase}${path}`;
    let body;
    if (params && method === "GET") {
      const query = formEncode(params).toString();
      if (query) url += `?${query}`;
    } else if (params) {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = formEncode(params).toString();
    }
    if (method === "POST") headers["Idempotency-Key"] = idempotencyKey || randomUUID();

    // A duplicate of an in-flight idempotent request gets 409 from Stripe;
    // wait for the first to finish and receive its stored response.
    let response;
    for (let attempt = 0; ; attempt++) {
      response = await fetchImpl(url, {
        method,
        headers,
        body,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (response.status !== 409 || method !== "POST" || attempt >= 3) break;
      await response.text();
      await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
    }
    const text = await response.text();
    let json;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      throw new StripeError(`Stripe returned non-JSON (HTTP ${response.status})`, { status: response.status });
    }
    if (!response.ok) {
      const err = json.error || {};
      throw new StripeError(err.message || `Stripe HTTP ${response.status}`, {
        status: response.status,
        type: err.type || "",
        code: err.code || "",
      });
    }
    return json;
  }

  return {
    get: (path, params) => request("GET", path, params),
    post: (path, params, options) => request("POST", path, params, options),
  };
}

// Verify a Stripe-Signature header against the raw request body.
// Returns the parsed event, or throws StripeError(status 400).
export function verifyWebhook(rawBody, header, secret, { toleranceSeconds = 300, now = Date.now() } = {}) {
  if (!secret) throw new StripeError("STRIPE_WEBHOOK_SECRET is not set", { status: 500, type: "configuration" });
  if (!header) throw new StripeError("missing Stripe-Signature header", { status: 400 });

  let timestamp = "";
  const signatures = [];
  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === "t") timestamp = value;
    else if (key === "v1") signatures.push(value);
  }
  if (!/^\d+$/.test(timestamp) || signatures.length === 0) {
    throw new StripeError("malformed Stripe-Signature header", { status: 400 });
  }
  const age = Math.abs(now / 1000 - Number(timestamp));
  if (age > toleranceSeconds) throw new StripeError("webhook timestamp outside tolerance", { status: 400 });

  const expected = createHmac("sha256", secret).update(`${timestamp}.${rawBody}`, "utf8").digest();
  const matched = signatures.some((candidate) => {
    if (!/^[0-9a-f]{64}$/.test(candidate)) return false;
    return timingSafeEqual(Buffer.from(candidate, "hex"), expected);
  });
  if (!matched) throw new StripeError("webhook signature mismatch", { status: 400 });

  try {
    return JSON.parse(rawBody);
  } catch {
    throw new StripeError("webhook body is not JSON", { status: 400 });
  }
}

// Build a header the way Stripe does (used by tests and local tooling).
export function signWebhook(rawBody, secret, timestamp = Math.floor(Date.now() / 1000)) {
  const v1 = createHmac("sha256", secret).update(`${timestamp}.${rawBody}`, "utf8").digest("hex");
  return `t=${timestamp},v1=${v1}`;
}
