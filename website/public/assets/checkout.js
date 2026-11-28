// Starts Stripe Checkout for a self-serve support plan.
// The page sends only the plan choice; /api/checkout looks up the price in
// Stripe and returns the Checkout URL. Errors reject with a localized message.
(function () {
  "use strict";

  var MESSAGES = {
    en: {
      network: "Could not reach the checkout service. Check your connection and try again.",
      unavailable: "This plan is not available for online checkout. Please contact us.",
      invalid: "That plan selection was not accepted. Please reload the page and try again.",
      server: "Checkout is temporarily unavailable. Please try again shortly or contact us.",
      stale: "Plans or prices have changed since this page loaded. Reload the page and try again.",
    },
    ja: {
      network: "決済サービスに接続できませんでした。通信環境をご確認のうえ、もう一度お試しください。",
      unavailable: "このプランはオンライン決済に対応していません。お問い合わせください。",
      invalid: "プランの選択を受け付けられませんでした。ページを再読み込みしてもう一度お試しください。",
      server: "現在、決済を開始できません。しばらくしてから再度お試しいただくか、お問い合わせください。",
      stale: "このページを開いた後にプランまたは価格が変更されました。ページを再読み込みしてから、もう一度お試しください。",
    },
  };

  function lang() {
    var l = (document.documentElement.getAttribute("lang") || "en").toLowerCase();
    return l.indexOf("ja") === 0 ? "ja" : "en";
  }

  // One id per page view: a double click or retry reuses it, so the server
  // passes the same Stripe idempotency key and gets the same Session back.
  function attemptId() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") return window.crypto.randomUUID();
    var bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.prototype.map.call(bytes, function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }
  var ATTEMPT = attemptId();

  function fail(key) {
    return Promise.reject(new Error(MESSAGES[lang()][key]));
  }

  window.KasumiCheckout = {
    start: function (options) {
      var body = JSON.stringify({
        tier: String(options && options.tier || ""),
        interval: String(options && options.interval || ""),
        currency: String(options && options.currency || "").toLowerCase(),
        locale: lang(),
        attempt: ATTEMPT,
        revision: String(window.KASUMI_PLANS && window.KASUMI_PLANS.revision || ""),
      });
      return fetch("/api/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body,
        credentials: "same-origin",
        cache: "no-store",
      }).then(
        function (response) {
          return response.json().catch(function () { return {}; }).then(function (data) {
            if (response.ok && data && typeof data.url === "string") {
              var target;
              try { target = new URL(data.url); } catch (e) { return fail("server"); }
              if (target.protocol !== "https:" && location.protocol === "https:") return fail("server");
              window.location.assign(target.href);
              return;
            }
            if (response.status === 409) return fail("stale");
            if (response.status === 404) return fail("unavailable");
            if (response.status >= 400 && response.status < 500) return fail("invalid");
            return fail("server");
          });
        },
        function () { return fail("network"); }
      );
    },
  };
})();
