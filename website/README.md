# kasumi.soramitsu.co.jp

The Kasumi landing page and the production-support checkout. Payments go to
Soramitsu Co., Ltd. through Stripe.

Static files live in `public/`. Two Vercel functions in `api/` create Stripe
Checkout Sessions and receive Stripe webhooks. There is no build step and no
npm dependency: the functions call the Stripe REST API with `fetch` and check
webhook signatures with `node:crypto`.

| Path | Purpose |
| --- | --- |
| `public/index.html`, `public/assets/site.{css,js}` | Landing page template (English, served at `/`) and its 3D parallax scene and behaviour |
| `public/assets/i18n.js` | All page text in English and Japanese, keyed by `data-i18n` attributes |
| `public/ja.html`, `public/en.html` | Prerendered language routes `/ja` and `/en` (generated; do not edit) |
| `scripts/prerender.mjs` | Writes `ja.html`, `en.html` and the text of `index.html` from `i18n.js` |
| `public/assets/plans.js` | **Single source of support-plan data**: tiers, prices, comparison matrix, severities, and the `selfServeOpen` sales switch |
| `public/assets/checkout.js` | Browser side of checkout: posts the chosen plan to `/api/checkout` |
| `public/legal/tokushoho.html` | 特定商取引法に基づく表記 (Japanese governs, English translation) |
| `public/legal/support-terms.html` | Support terms, refund policy and privacy notice (Japanese governs) |
| `public/thanks.html`, `public/404.html` | Post-checkout page, not-found page |
| `api/checkout.js` → `lib/checkout.js` | Checks the plan against `plans.js` and the Stripe Price, creates a subscription Checkout Session |
| `api/webhook.js` → `lib/webhook.js` | Verifies `Stripe-Signature`, posts Kasumi billing notices to Slack |
| `scripts/stripe-setup.mjs` | Creates/updates Stripe Products and Prices from `plans.js` (dry run by default) |
| `scripts/sync-chrome.mjs` | Copies the header and footer from `index.html` into the secondary pages |
| `scripts/launch-check.mjs` | Lists what still blocks live payments |
| `scripts/dev-server.mjs` | Local preview with the same headers, rewrites and clean URLs as `vercel.json` |
| `test/` | Unit tests, including an in-memory fake of the Stripe endpoints used |

## Run locally

Node 22 or newer.

```sh
cd website
npm test
npm run dev            # http://127.0.0.1:4318/ with a fake Stripe; no account needed
```

`npm run dev` seeds an in-memory Stripe from `plans.js`, so Subscribe goes to a
local "Fake Stripe Checkout" page and then to `/thanks`. Open the page at
`127.0.0.1`, not `localhost`: the checkout function only accepts requests from
`SITE_URL`. To use real Stripe test mode instead:

```sh
STRIPE_SECRET_KEY=sk_test_... node scripts/dev-server.mjs
```

Page text lives in `public/assets/i18n.js`. After changing it or the markup of
`index.html`, run `node scripts/prerender.mjs` so `/ja` and `/en` are real
Japanese and English HTML before any script runs (crawlers, link previews,
visitors without JavaScript). After editing the header or footer in
`index.html`, run `npm run sync-chrome`. Tests fail while either output is out
of date. The legal notice
repeats the JPY and USD prices, and a test checks them against `plans.js`.

## Plans, prices and the sales switch

The tiers follow a Codex (gpt-6.2-astra) survey, on 27 November 2026, of
published support offerings from MongoDB, Redis, CockroachDB, Couchbase, EDB,
Percona, Neo4j, ScyllaDB, YugabyteDB, TiDB, Elastic and Aiven, and the Japanese
vendors SRA OSS, Ashisuto and SmartStyle. Prices are pitched against the
Japanese self-managed vendors; response targets are ones a Tokyo team can
staff.

| | Standard | Business | Enterprise |
| --- | --- | --- | --- |
| Monthly (excl. tax) | ¥60,000 / $400 | ¥180,000 / $1,200 | from ¥900,000 / $6,000 |
| Annual, paid upfront | ¥660,000 / $4,400 | ¥1,980,000 / $13,200 | from ¥9,900,000 / $66,000 |
| Sev 1 initial response | 4 business hours | 2 business hours | 1 hour, 24×7 |
| How to buy | Stripe Checkout | Stripe Checkout | Signed order (contact) |

A design-partner pilot (four weeks, fixed fee after scoping) is offered by
email for teams still evaluating.

`selfServeOpen` in `plans.js` is the one switch for online sales. When false,
the page shows contact buttons instead of Subscribe, **and** `/api/checkout`
refuses to create sessions, so a hidden button cannot leave the purchase path
open. Codex recommended keeping it false until a release is qualified; it is
currently `true` because self-serve sales were requested.

The browser posts only `{tier, interval, currency, locale, attempt}`. The
function refuses the request unless the tier is a self-serve tier in
`plans.js`, then looks up the Price with lookup key
`kasumi_support_<tier>_<interval>_<currency>` and refuses it unless its
product id, amount, currency, interval, tax behaviour (`exclusive`) and
metadata match `plans.js` exactly. Amounts never come from the browser.
Success and cancel URLs are built from `SITE_URL`, never from the Host header;
the returned URL must be on `https://checkout.stripe.com`. Each page view sends
one `attempt` id, used as the Stripe idempotency key, so a double click or
retry returns the same Session. In live mode the function also refuses to sell
unless `STRIPE_AUTOMATIC_TAX=true` and `STRIPE_REQUIRE_TERMS=true`.

The page also sends the catalog `revision` from `plans.js`; the function
answers 409 ("reload the page") when it differs, so a tab opened before a price
change cannot buy at a price it never showed. Stripe's cancel URL returns the
buyer to `/{lang}?interval=…&currency=…#support` with their selection intact.
Checkout offers cards only, matching the legal notice.

To change a price, edit `public/assets/plans.js` (bump `revision`) and the
legal notice, then run the setup script. To change the support terms, edit
`public/legal/support-terms.html`, copy it to a new
`public/legal/support-terms-<date>.html`, set `termsVersion` to that date and
add the page to `PAGES` in `scripts/sync-chrome.mjs`; Checkout links to the
versioned copy and records `kasumi_terms` on every subscription. Old versioned
copies stay published unchanged.

After changing prices, run the setup script. Stripe Prices are immutable, so it creates a new Price,
moves the lookup key and archives the old Price; any other active Price left on
a Kasumi product (for example from an interrupted run) is archived on the next
run. Prices are flat, licensed, per-unit; the function refuses metered,
tiered or quantity-transformed Prices. Existing subscribers stay on
their old Price until you migrate them in the Stripe Dashboard.

```sh
STRIPE_SECRET_KEY=sk_test_... npm run stripe:setup              # dry run
STRIPE_SECRET_KEY=sk_test_... npm run stripe:setup -- --apply
STRIPE_SECRET_KEY=sk_live_... npm run stripe:setup -- --apply --live
```

Products get tax code `txcd_20060017` (technical support services) from
`plans.js`; have Soramitsu's tax adviser confirm it.

## Billing notices and fulfilment

Stripe is the system of record. The webhook keeps no state: for Kasumi events
only (identified by `kasumi_tier` metadata or a `kasumi_support_` lookup key)
it posts a Slack notice with the plan, amount, billing country and a Dashboard
link, without customer names, emails or tax IDs. Support staff activate,
renew or close support after checking the subscription and its paid invoice in
the Dashboard. Handled events: `checkout.session.completed`, `invoice.paid`,
`invoice.payment_failed`, `invoice.payment_action_required`,
`customer.subscription.updated` (cancellation scheduled or status change) and
`customer.subscription.deleted`. A failed notice returns 500 so Stripe
retries; a duplicate notice after a retry is harmless.

## Deploy

1. **Stripe account (Soramitsu Co., Ltd., already exists)** — in the Dashboard.
   Products and Prices use `kasumi_support_` ids and lookup keys, so they sit
   beside the account's other products without colliding:
   - Settings → Public details: business name, support email and statement
     descriptor. Stripe requires an account-level terms-of-service URL before
     Checkout can show the terms checkbox; if the account already has one for
     another product, keep it: the checkbox text the function sends links to
     `https://kasumi.soramitsu.co.jp/legal/support-terms` itself.
   - Tax → register Japan (consumption tax) and any other registrations, set
     the head-office origin address, and add the seller's qualified-invoice
     number (`jp_trn`, T + 13 digits) as an account tax ID so invoices carry
     it. Check a finalized test invoice for JPY and for USD (a USD qualified
     invoice must also show the JCT in yen).
   - Billing → Customer portal: allow cancellation (at period end) and
     payment-method updates, enable the login link, and put that
     `https://billing.stripe.com/p/login/...` URL in `portalUrl` in `plans.js`.
   - Developers → Webhooks: add `https://kasumi.soramitsu.co.jp/api/webhook`
     for the events listed above; copy its signing secret.
   - Run the setup script with a test key, buy each plan in test mode
     (including 3D Secure test cards), then repeat the setup with the live key.
   - Validate the pinned API version (`2026-02-25.clover` in `lib/stripe.js`)
     in a sandbox: Checkout uses `name_collection` and `adaptive_pricing`.
2. **Vercel** — new project from this repository with Root Directory
   `website`, Framework Preset "Other", no build command, output directory
   `public`, Node.js 22. Add the variables from `.env.example` for Production
   (live key) and Preview (test key, and `SITE_URL` set to the preview origin
   if you test checkout there). Consider a Vercel Firewall rate-limit rule on
   `/api/checkout`.
3. **Domain** — add `kasumi.soramitsu.co.jp` to the Vercel project, then in
   Route 53 (soramitsu.co.jp zone) create exactly the CNAME record Vercel
   shows for it.
4. Have counsel review the legal pages (the 特定商取引法 page names
   宮沢 和正 as head of operations, phone 050-5526-4670, email
   service@soramitsu.co.jp), and run `npm run launch-check` until it passes.
5. Buy the cheapest plan in live mode, check the Slack notice and the
   invoice, and cancel it from the customer portal.
