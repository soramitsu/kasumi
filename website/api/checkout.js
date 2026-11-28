// Vercel function: POST /api/checkout. Logic lives in lib/checkout.js.
import { handleCheckout } from "../lib/checkout.js";

export function POST(request) {
  return handleCheckout(request);
}
