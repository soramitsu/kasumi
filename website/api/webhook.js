// Vercel function: POST /api/webhook (Stripe events). Logic lives in lib/webhook.js.
import { handleWebhook } from "../lib/webhook.js";

export function POST(request) {
  return handleWebhook(request);
}
