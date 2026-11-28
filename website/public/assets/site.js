// Kasumi website behaviour: language toggle, hero parallax, section motion,
// retry explainer and support-plan rendering. No dependencies.
//
// Text lives in i18n.js (window.KASUMI_STRINGS), keyed by the data-i18n
// attributes in the HTML. In a string, `backticks` become <code> and | marks
// where a Japanese heading may wrap. Elements may also carry
// data-i18n-attr="attribute:key;...". scripts/prerender.mjs applies the same
// rules to write ja.html and en.html, so keep setRich() and it in step.
(function () {
  "use strict";

  var win = window;
  var doc = document;
  var root = doc.documentElement;
  root.classList.remove("no-js");
  root.classList.add("js");

  // ───────────── Text ─────────────
  // The dictionary is window.KASUMI_STRINGS from i18n.js. Without it the page
  // keeps the text in its HTML and the script never writes an empty string.
  var DICT = win.KASUMI_STRINGS;
  var hasStrings = !!(DICT && DICT.en && typeof DICT.en === "object");
  var STRINGS = { en: hasStrings ? DICT.en : {}, ja: (hasStrings && DICT.ja) || {} };

  // ───────────── Small helpers ─────────────
  function $(sel, ctx) { return (ctx || doc).querySelector(sel); }
  function $$(sel, ctx) { return Array.prototype.slice.call((ctx || doc).querySelectorAll(sel)); }
  function clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }
  function smooth(a, b, v) { var x = clamp((v - a) / (b - a), 0, 1); return x * x * (3 - 2 * x); }
  function el(tag, attrs, children) {
    var node = doc.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        var value = attrs[key];
        if (value === null || value === undefined || value === false) return;
        if (key === "class") node.className = value;
        else if (key === "text") node.textContent = value;
        else node.setAttribute(key, value === true ? "" : value);
      });
    }
    (children || []).forEach(function (child) {
      if (child === null || child === undefined || child === false) return;
      node.appendChild(typeof child === "string" ? doc.createTextNode(child) : child);
    });
    return node;
  }

  var mqReduce = win.matchMedia ? win.matchMedia("(prefers-reduced-motion: reduce)") : { matches: false };
  var mqFine = win.matchMedia ? win.matchMedia("(hover: hover) and (pointer: fine)") : { matches: true };
  function onMedia(mq, fn) {
    if (mq.addEventListener) mq.addEventListener("change", fn);
    else if (mq.addListener) mq.addListener(fn);
  }
  function reduced() { return !!mqReduce.matches; }

  // ───────────── Language ─────────────
  var LANG_KEY = "kasumi.lang";
  var lang = "en";
  var langListeners = [];

  // /ja and /en are this page prerendered in each language (ja.html, en.html).
  function pathLang() {
    var m = /^\/(ja|en)\/?$/.exec(win.location.pathname);
    return m ? m[1] : null;
  }
  function isHome() { return !!pathLang() || win.location.pathname === "/"; }
  function has(key) { return STRINGS[lang][key] !== undefined || STRINGS.en[key] !== undefined; }

  function pickLang() {
    var fromPath = pathLang();
    if (fromPath) {
      try { win.localStorage.setItem(LANG_KEY, fromPath); } catch (e) { /* storage may be blocked */ }
      return fromPath;
    }
    // Without the dictionary the home page can only show the language of its HTML.
    if (!hasStrings && isHome()) return /^ja\b/i.test(root.getAttribute("lang") || "") ? "ja" : "en";
    var fromUrl = null;
    try { fromUrl = new URLSearchParams(win.location.search).get("lang"); } catch (e) { /* ignore */ }
    if (fromUrl === "en" || fromUrl === "ja") {
      // A language link is an explicit choice: keep it for the next page too.
      try { win.localStorage.setItem(LANG_KEY, fromUrl); } catch (e) { /* storage may be blocked */ }
      return fromUrl;
    }
    try {
      var stored = win.localStorage.getItem(LANG_KEY);
      if (stored === "en" || stored === "ja") return stored;
    } catch (e) { /* storage may be blocked */ }
    // The first language we have, in the browser's order of preference.
    var prefs = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language];
    for (var i = 0; i < prefs.length; i++) {
      var m = /^(ja|en)\b/i.exec(String(prefs[i] || ""));
      if (m) return m[1].toLowerCase();
    }
    return "en";
  }

  function t(key, vars) {
    var s = STRINGS[lang][key];
    if (s === undefined) s = STRINGS.en[key];
    if (s === undefined) return "";
    if (vars) Object.keys(vars).forEach(function (k) { s = s.split("{" + k + "}").join(vars[k]); });
    return s;
  }

  // Plan data may hold a plain string or {en, ja}.
  function L(value) {
    if (value === null || value === undefined) return "";
    if (typeof value === "string") return value;
    if (typeof value === "number") return String(value);
    if (typeof value === "object") return String(value[lang] || value.en || value.ja || "");
    return "";
  }

  // `code` spans and | phrase breaks, built with DOM nodes (never innerHTML).
  function setRich(node, text) {
    if (text.indexOf("`") < 0 && text.indexOf("|") < 0) { node.textContent = text; return; }
    while (node.firstChild) node.removeChild(node.firstChild);
    text.split("`").forEach(function (part, i) {
      if (i % 2) { node.appendChild(el("code", { text: part })); return; }
      if (part.indexOf("|") < 0) { if (part) node.appendChild(doc.createTextNode(part)); return; }
      part.split("|").forEach(function (phrase) {
        var body = phrase.replace(/\s+$/, "");
        if (body) node.appendChild(el("span", { class: "ph", text: body }));
        if (body !== phrase) node.appendChild(doc.createTextNode(" "));
      });
    });
  }

  function applyStrings(scope) {
    $$("[data-i18n]", scope).forEach(function (node) {
      var key = node.getAttribute("data-i18n");
      if (has(key)) setRich(node, t(key));
    });
    $$("[data-i18n-attr]", scope).forEach(function (node) {
      node.getAttribute("data-i18n-attr").split(";").forEach(function (pair) {
        var bits = pair.split(":");
        if (bits.length !== 2) return;
        var key = bits[1].trim();
        if (has(key)) node.setAttribute(bits[0].trim(), t(key));
      });
    });
  }

  function setLang(next, persist) {
    lang = next === "ja" ? "ja" : "en";
    root.setAttribute("lang", lang);
    applyStrings(doc);
    $$(".lang__opt[data-lang]").forEach(function (a) {
      if (a.getAttribute("data-lang") === lang) a.setAttribute("aria-current", "true");
      else a.removeAttribute("aria-current");
    });
    if (persist) {
      try { win.localStorage.setItem(LANG_KEY, lang); } catch (e) { /* ignore */ }
      // The home page keeps the choice in its path (/ja, /en); other pages in ?lang=.
      try {
        var url = new URL(win.location.href);
        if (isHome()) { url.pathname = "/" + lang; url.searchParams.delete("lang"); }
        else url.searchParams.set("lang", lang);
        win.history.replaceState(null, "", url.pathname + url.search + url.hash);
      } catch (e) { /* ignore */ }
    }
    // On a language route the canonical URL follows the language shown.
    var canonical = $('link[rel="canonical"]');
    if (canonical && pathLang()) {
      try {
        var target = new URL(canonical.getAttribute("href"), win.location.href);
        target.pathname = "/" + lang;
        canonical.setAttribute("href", target.href);
      } catch (e) { /* ignore */ }
    }
    langListeners.forEach(function (fn) { fn(lang); });
    try { doc.dispatchEvent(new CustomEvent("kasumi:langchange", { detail: { lang: lang } })); } catch (e) { /* ignore */ }
  }

  function initLang() {
    $$(".lang__opt[data-lang]").forEach(function (a) {
      a.addEventListener("click", function (event) {
        // Without the dictionary, follow the link to the prerendered /ja or /en.
        if (!hasStrings && isHome()) return;
        event.preventDefault();
        setLang(a.getAttribute("data-lang"), true);
      });
    });
    setLang(pickLang(), false);
  }

  // ───────────── Header ─────────────
  function initHeader() {
    var header = $(".site-header");
    if (!header) return;
    var toggle = $(".nav-toggle", header);
    var nav = $(".site-nav", header);
    var ticking = false;

    function paint() {
      ticking = false;
      header.classList.toggle("is-scrolled", (win.scrollY || win.pageYOffset || 0) > 12);
    }
    win.addEventListener("scroll", function () {
      if (!ticking) { ticking = true; win.requestAnimationFrame(paint); }
    }, { passive: true });
    paint();

    if (!toggle || !nav) return;
    function setOpen(open) {
      header.classList.toggle("is-open", open);
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    }
    toggle.addEventListener("click", function () { setOpen(toggle.getAttribute("aria-expanded") !== "true"); });
    nav.addEventListener("click", function (event) {
      if (event.target && event.target.closest && event.target.closest("a")) setOpen(false);
    });
    doc.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") { setOpen(false); toggle.focus(); }
    });
    doc.addEventListener("click", function (event) {
      if (toggle.getAttribute("aria-expanded") === "true" && !header.contains(event.target)) setOpen(false);
    });
  }

  // ───────────── Hero scene ─────────────
  // Every .layer has a distance from the camera (data-depth; the rocks are at
  // 1000). Each frame the camera position is turned into one transform per
  // layer: scale = depth / (depth - cameraZ) about the vanishing point, plus a
  // sideways shift that grows as layers get nearer. Scrolling moves the camera
  // forward; the pointer moves it sideways while it keeps looking at a point
  // just behind the rocks, so far layers and near layers slide opposite ways.
  function initScene() {
    var hero = $(".hero");
    if (!hero || !win.requestAnimationFrame) return;
    var pin = $(".hero__pin", hero);
    var stage = $(".stage", hero);
    var fog = $(".hero__fog", hero);
    var content = $(".hero__content", hero);
    if (!pin || !stage) return;

    var layers = $$(".layer", stage).map(function (node, i) {
      return {
        node: node,
        depth: parseFloat(node.getAttribute("data-depth")) || 1000,
        k: 1 / (parseFloat(node.getAttribute("data-oversize")) || 1),
        drift: parseFloat(node.getAttribute("data-drift")) || 0,
        rise: node.hasAttribute("data-rise"),
        phase: i * 1.7,
        vx: 0, vy: 0, lastT: "", lastO: "",
      };
    });

    var FOCUS = 0.62;            // 1000 / distance of the point the camera looks at
    var NEAR = 30;               // layers closer than this are behind the lens
    var stageW = 1, stageH = 1, pinDist = 0, pinH = 1, unit = 1;
    var targetX = 0, targetY = 0, camX = 0, camY = 0;
    var visible = true, running = false, hiddenContent = false;
    var lastFog = "", lastContentT = "", lastContentO = "";

    function measure() {
      stageW = stage.offsetWidth || 1;
      stageH = stage.offsetHeight || 1;
      unit = clamp(stageW / 1100, 0.45, 1.25);
      var vx = stageW * 0.5804, vy = stageH * 0.6;
      layers.forEach(function (l) {
        l.vx = vx - l.node.offsetLeft;
        l.vy = vy - l.node.offsetTop;
      });
      pinH = pin.offsetHeight || 1;
      pinDist = Math.max(0, hero.offsetHeight - pinH);
    }

    function clear() {
      layers.forEach(function (l) { l.node.style.transform = ""; l.node.style.opacity = ""; l.lastT = l.lastO = ""; });
      if (fog) fog.style.opacity = "";
      if (content) { content.style.transform = ""; content.style.opacity = ""; content.style.visibility = ""; }
      lastFog = lastContentT = lastContentO = ""; hiddenContent = false;
    }

    function frame(now) {
      if (!running) return;
      var time = now / 1000;
      var sy = win.scrollY || win.pageYOffset || 0;
      var pinned = pinDist > 4;
      var p = pinned ? clamp(sy / pinDist, 0, 1) : clamp(sy / (pinH * 0.85), 0, 1);
      var e = smooth(0, 1, p);
      var camZ = e * (pinned ? 430 : 250);
      var lag = (pinned ? Math.max(0, sy - pinDist) : sy) * 0.3;

      camX += (targetX * 36 * unit - camX) * 0.07;
      camY += (targetY * 20 * unit - camY) * 0.07;

      for (var i = 0; i < layers.length; i++) {
        var l = layers[i];
        var dz = l.depth - camZ;
        var o, tr;
        if (dz <= NEAR) {
          o = "0";
          tr = l.lastT;
        } else {
          var s = l.depth / dz;
          var look = 1000 / dz - FOCUS;
          var tx = l.vx * (1 - s) - camX * look;
          var ty = l.vy * (1 - s) - camY * look + lag;
          if (l.drift) tx += Math.sin(time * 0.21 + l.phase) * l.drift * unit * s;
          if (l.rise) ty -= e * stageH * 0.07;
          tr = "translate3d(" + tx.toFixed(1) + "px," + ty.toFixed(1) + "px,0) scale(" + (s * l.k).toFixed(4) + ")";
          o = l.depth < 1000 ? clamp((dz - NEAR) / 170, 0, 1).toFixed(2) : "1";
          if (o === "1.00") o = "1";
        }
        if (tr !== l.lastT) { l.node.style.transform = tr; l.lastT = tr; }
        if (o !== l.lastO) { l.node.style.opacity = o; l.lastO = o; }
      }

      if (fog) {
        var f = ((pinned ? smooth(0.5, 1, p) : smooth(0.25, 0.95, p)) * 0.94).toFixed(2);
        if (f !== lastFog) { fog.style.opacity = f; lastFog = f; }
      }
      if (content) {
        var co = pinned ? (1 - smooth(0.04, 0.36, p)).toFixed(2) : "1";
        var ct = "translate3d(" + (camX * 0.14).toFixed(1) + "px," + (pinned ? -p * 110 : 0).toFixed(1) + "px,0)";
        if (ct !== lastContentT) { content.style.transform = ct; lastContentT = ct; }
        if (co !== lastContentO) { content.style.opacity = co; lastContentO = co; }
        var hide = co === "0.00";
        if (hide !== hiddenContent) { content.style.visibility = hide ? "hidden" : ""; hiddenContent = hide; }
      }
      win.requestAnimationFrame(frame);
    }

    function sync() {
      var should = visible && !reduced() && !doc.hidden;
      hero.classList.toggle("is-idle", !should);
      if (should && !running) { running = true; win.requestAnimationFrame(frame); }
      else if (!should && running) { running = false; }
      if (reduced()) clear();
    }

    win.addEventListener("pointermove", function (event) {
      if (event.pointerType === "touch" || !mqFine.matches) return;
      targetX = clamp(event.clientX / (win.innerWidth || 1) * 2 - 1, -1, 1);
      targetY = clamp(event.clientY / (win.innerHeight || 1) * 2 - 1, -1, 1);
    }, { passive: true });
    root.addEventListener("pointerleave", function () { targetX = 0; targetY = 0; });

    if ("IntersectionObserver" in win) {
      new IntersectionObserver(function (entries) {
        visible = entries[entries.length - 1].isIntersecting;
        sync();
      }, { rootMargin: "80px 0px" }).observe(hero);
    }
    if ("ResizeObserver" in win) {
      var ro = new ResizeObserver(function () { measure(); });
      ro.observe(hero); ro.observe(stage);
    } else {
      win.addEventListener("resize", measure);
    }
    doc.addEventListener("visibilitychange", sync);
    onMedia(mqReduce, function () { measure(); sync(); });
    if (doc.fonts && doc.fonts.ready) doc.fonts.ready.then(measure);
    measure();
    sync();
  }

  // ───────────── Scroll-linked mist bands between sections ─────────────
  function initBands() {
    var bands = $$("[data-speed]").map(function (node) {
      return { node: node, speed: parseFloat(node.getAttribute("data-speed")) || 0, top: 0, last: "" };
    });
    if (!bands.length || !win.requestAnimationFrame) return;
    var vh = win.innerHeight || 1, ticking = false;

    function measure() {
      var sy = win.scrollY || win.pageYOffset || 0;
      vh = win.innerHeight || 1;
      bands.forEach(function (b) { b.top = b.node.getBoundingClientRect().top + sy; });
      paint();
    }
    function paint() {
      ticking = false;
      if (reduced()) {
        bands.forEach(function (b) { if (b.last) { b.node.style.transform = ""; b.last = ""; } });
        return;
      }
      var sy = win.scrollY || win.pageYOffset || 0;
      bands.forEach(function (b) {
        var c = (b.top - sy - vh / 2) / vh;
        if (c < -1 || c > 1) return;
        var tr = "translate3d(" + (c * b.speed).toFixed(1) + "px,0,0)";
        if (tr !== b.last) { b.node.style.transform = tr; b.last = tr; }
      });
    }
    win.addEventListener("scroll", function () {
      if (!ticking) { ticking = true; win.requestAnimationFrame(paint); }
    }, { passive: true });
    if ("ResizeObserver" in win) new ResizeObserver(measure).observe(doc.body);
    else win.addEventListener("resize", measure);
    onMedia(mqReduce, paint);
    measure();
  }

  // ───────────── Reveal on scroll, deck fan-out ─────────────
  function initReveal() {
    var items = $$(".reveal");
    var decks = $$("[data-deck]");
    if (!("IntersectionObserver" in win)) {
      items.concat(decks).forEach(function (node) { node.classList.add("is-in"); });
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      var n = 0;
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var node = entry.target;
        node.style.setProperty("--d", String(Math.min(n++, 5)));
        node.classList.add("is-in");
        io.unobserve(node);
        win.setTimeout(function () { node.style.removeProperty("--d"); }, 1500);
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -6% 0px" });
    items.forEach(function (node) { io.observe(node); });

    var deckIo = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-in");
        deckIo.unobserve(entry.target);
      });
    }, { threshold: 0.22 });
    decks.forEach(function (node) { deckIo.observe(node); });
  }

  // ───────────── Pointer tilt ─────────────
  function initTilt() {
    $$("[data-tilt]").forEach(function (node) {
      var max = parseFloat(node.getAttribute("data-tilt-max")) || 7;
      var rect = null, raf = 0, px = 0.5, py = 0.5;

      function apply() {
        raf = 0;
        if (!rect) return;
        node.style.setProperty("--ry", ((px - 0.5) * 2 * max).toFixed(2) + "deg");
        node.style.setProperty("--rx", ((0.5 - py) * 2 * max).toFixed(2) + "deg");
        node.style.setProperty("--gx", (px * rect.width).toFixed(0) + "px");
        node.style.setProperty("--gy", (py * rect.height).toFixed(0) + "px");
      }
      function reset() {
        rect = null;
        node.classList.remove("is-tilting");
        node.style.removeProperty("--rx");
        node.style.removeProperty("--ry");
      }
      node.addEventListener("pointerenter", function (event) {
        if (event.pointerType === "touch" || !mqFine.matches || reduced()) return;
        rect = node.getBoundingClientRect();
        node.classList.add("is-tilting");
      });
      node.addEventListener("pointermove", function (event) {
        if (!rect) return;
        px = clamp((event.clientX - rect.left) / rect.width, 0, 1);
        py = clamp((event.clientY - rect.top) / rect.height, 0, 1);
        if (!raf) raf = win.requestAnimationFrame(apply);
      });
      node.addEventListener("pointerleave", reset);
      win.addEventListener("scroll", function () { if (rect) reset(); }, { passive: true });
    });
  }

  // ───────────── Retry explainer ─────────────
  function initRetry() {
    var box = $("[data-retry]");
    if (!box) return;
    var buttons = $$(".retry__step", box);
    var toggle = $("[data-retry-toggle]", box);
    var label = $("[data-retry-toggle-label]", box);
    var STEP_MS = 3400;
    var step = 1, userPaused = false, visible = false, timer = 0;

    function show(n) {
      step = n;
      box.setAttribute("data-step", "0");
      void box.offsetWidth;   // restart the step's CSS animations
      box.setAttribute("data-step", String(n));
      buttons.forEach(function (b, i) {
        if (i + 1 === n) b.setAttribute("aria-current", "step");
        else b.removeAttribute("aria-current");
      });
    }
    function sync(restart) {
      win.clearTimeout(timer);
      var playing = visible && !userPaused && !reduced() && !doc.hidden;
      var wasPaused = box.classList.contains("is-paused");
      box.classList.toggle("is-playing", playing);
      box.classList.toggle("is-paused", !playing && !reduced());
      if (playing) {
        if (restart || wasPaused) show(step);
        timer = win.setTimeout(function () { show(step % buttons.length + 1); sync(false); }, STEP_MS);
      }
    }
    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        show(parseInt(b.getAttribute("data-step-to"), 10) || 1);
        sync(false);
        // While paused, a chosen step still plays through once.
        if (userPaused) box.classList.remove("is-paused");
      });
    });
    if (toggle) {
      toggle.addEventListener("click", function () {
        userPaused = !userPaused;
        toggle.setAttribute("data-paused", userPaused ? "true" : "false");
        var key = userPaused ? "retry.play" : "retry.pause";
        if (label && has(key)) { label.setAttribute("data-i18n", key); setRich(label, t(key)); }
        sync(false);
      });
    }
    if ("IntersectionObserver" in win) {
      new IntersectionObserver(function (entries) {
        visible = entries[entries.length - 1].isIntersecting;
        sync(false);
      }, { threshold: 0.3 }).observe(box);
    }
    doc.addEventListener("visibilitychange", function () { sync(false); });
    onMedia(mqReduce, function () { sync(true); });
    buttons[0] && buttons[0].setAttribute("aria-current", "step");
    sync(false);
  }

  // ───────────── Copy buttons ─────────────
  function initCopy() {
    $$("[data-copy]").forEach(function (button) {
      var source = $(button.getAttribute("data-copy"));
      var labelNode = $("[data-i18n]", button);
      var figure = button.closest ? button.closest("figure") : null;
      var status = figure ? $("[data-copy-status]", figure) : null;
      if (!source) return;
      var timer = 0;
      function say(key) {
        if (labelNode && has(key)) { labelNode.setAttribute("data-i18n", key); setRich(labelNode, t(key)); }
        if (status) status.textContent = key === "qs.copy" ? "" : t(key);
        win.clearTimeout(timer);
        if (key !== "qs.copy") timer = win.setTimeout(function () { say("qs.copy"); }, 2400);
      }
      function selectSource() {
        try {
          var range = doc.createRange();
          range.selectNodeContents(source);
          var sel = win.getSelection();
          sel.removeAllRanges();
          sel.addRange(range);
        } catch (e) { /* ignore */ }
        say("qs.copyfail");
      }
      button.addEventListener("click", function () {
        var text = source.textContent || "";
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () { say("qs.copied"); }, selectSource);
        } else {
          selectSource();
        }
      });
    });
  }

  // ───────────── Code blocks: a keyboard stop only while they overflow ─────────────
  function initScrollers() {
    var blocks = $$(".code__body");
    if (!blocks.length) return;
    function fit() {
      blocks.forEach(function (node) {
        if (node.scrollWidth > node.clientWidth + 1) node.setAttribute("tabindex", "0");
        else node.removeAttribute("tabindex");
      });
    }
    if ("ResizeObserver" in win) {
      var ro = new ResizeObserver(fit);
      blocks.forEach(function (node) { ro.observe(node); });
    } else {
      win.addEventListener("resize", fit);
    }
    fit();
  }

  // ───────────── Support plans (window.KASUMI_PLANS) ─────────────
  function initPlans() {
    var host = $("[data-plans]");
    var data = win.KASUMI_PLANS;
    var email = data && typeof data.contactEmail === "string" && /^[^@\s<>"]+@[^@\s<>"]+$/.test(data.contactEmail) ? data.contactEmail : "";

    if (email) {
      $$("[data-contact-email]").forEach(function (a) { a.setAttribute("href", "mailto:" + email); a.textContent = email; });
    }
    // Without plan data or the dictionary, the contact line in the HTML stays.
    if (!host || !hasStrings || !data || !Array.isArray(data.tiers) || !data.tiers.length) return;

    var tiers = data.tiers.filter(function (tier) { return tier && typeof tier.id === "string"; });
    var known = ["month", "year"];
    var intervals = (Array.isArray(data.intervals) ? data.intervals : known).filter(function (v) { return known.indexOf(v) >= 0; });
    if (!intervals.length) intervals = ["month"];
    var currencies = (Array.isArray(data.currencies) ? data.currencies : []).filter(function (v) { return typeof v === "string" && /^[A-Za-z]{3}$/.test(v); })
      .map(function (v) { return v.toUpperCase(); });
    if (!currencies.length) currencies = ["JPY"];
    var state = {
      currency: currencies.indexOf(String(data.defaultCurrency || "").toUpperCase()) >= 0 ? String(data.defaultCurrency).toUpperCase() : currencies[0],
      interval: intervals.indexOf(data.defaultInterval) >= 0 ? data.defaultInterval : intervals[0],
    };
    // Stripe's cancel URL comes back as /{lang}?interval=…&currency=…#support.
    // Restore that selection, then drop the two parameters from the address.
    try {
      var here = new URL(win.location.href);
      if (here.searchParams.has("interval") || here.searchParams.has("currency")) {
        var wantInterval = here.searchParams.get("interval");
        var wantCurrency = String(here.searchParams.get("currency") || "").toUpperCase();
        if (intervals.indexOf(wantInterval) >= 0) state.interval = wantInterval;
        if (currencies.indexOf(wantCurrency) >= 0) state.currency = wantCurrency;
        here.searchParams.delete("interval");
        here.searchParams.delete("currency");
        win.history.replaceState(win.history.state, "", here.pathname + here.search + here.hash);
      }
    } catch (e) { /* keep the defaults */ }

    // The checkout in flight, if any: {tier: id}. It is kept outside render(),
    // which rebuilds every control on a language change, so a rebuilt Subscribe
    // button stays disabled and cannot start a second Stripe session.
    var pending = null;
    var resetTimer = 0, refs = {};

    function amountOf(tier, currency, interval) {
      var v = tier.price && tier.price[currency] ? tier.price[currency][interval] : null;
      return typeof v === "number" && isFinite(v) && v >= 0 ? v : null;
    }
    function money(amount, currency) {
      var whole = Math.round(amount) === amount;
      var digits = currency === "JPY" || whole ? 0 : 2;
      var out;
      try {
        out = new Intl.NumberFormat(lang === "ja" ? "ja-JP" : "en-US", {
          style: "currency", currency: currency, minimumFractionDigits: digits, maximumFractionDigits: digits,
        }).format(amount);
      } catch (e) {
        out = amount.toFixed(digits) + " " + currency;
      }
      return out.replace("￥", "¥");   // full-width yen sign to the ordinary one
    }
    function symbol(currency) {
      try {
        var parts = new Intl.NumberFormat("en-US", { style: "currency", currency: currency }).formatToParts(0);
        for (var i = 0; i < parts.length; i++) if (parts[i].type === "currency") return parts[i].value;
      } catch (e) { /* ignore */ }
      return "";
    }
    function saving(tier, currency) {
      var m = amountOf(tier, currency, "month"), y = amountOf(tier, currency, "year");
      if (m === null || y === null || m <= 0) return null;
      var diff = m * 12 - y;
      return diff > 0 ? { amount: diff, pct: Math.round(diff / (m * 12) * 100) } : null;
    }
    function bestSaving() {
      var max = 0, min = Infinity, any = false;
      tiers.forEach(function (tier) {
        if (!tier.checkout) return;   // a quoted tier has no fixed annual saving
        var s = saving(tier, state.currency);
        if (s && s.pct > 0) { any = true; max = Math.max(max, s.pct); min = Math.min(min, s.pct); }
      });
      return any ? { pct: max, uniform: max === min } : null;
    }

    function segment(name, legend, options, current) {
      var set = el("fieldset", { class: "seg", "data-seg": name }, [el("legend", { class: "sr-only", text: legend })]);
      options.forEach(function (opt) {
        var input = el("input", { type: "radio", name: "kasumi-" + name, value: opt.value, checked: opt.value === current });
        input.checked = opt.value === current;
        input.addEventListener("change", function () {
          if (!input.checked || pending) return;
          state[name] = opt.value;
          renderBody();
        });
        var text = el("span", { class: "seg__label" }, [opt.label]);
        if (opt.extra) text.appendChild(opt.extra);
        set.appendChild(el("label", null, [input, text]));
      });
      return set;
    }

    function tierCard(tier) {
      var name = L(tier.name) || tier.id;
      var featured = !!tier.featured;
      var anyFeatured = tiers.some(function (x) { return x.featured; });
      var amount = amountOf(tier, state.currency, state.interval);
      var nameId = "tier-" + tier.id + "-name";
      var card = el("article", { class: "tier" + (featured ? " tier--featured" : ""), "aria-labelledby": nameId });
      if (featured) card.appendChild(el("p", { class: "tier__flag", text: t("sup.recommended") }));
      if (L(tier.audience)) card.appendChild(el("p", { class: "tier__audience", text: L(tier.audience) }));
      card.appendChild(el("h3", { class: "tier__name", id: nameId, text: name }));
      if (L(tier.summary)) card.appendChild(el("p", { class: "tier__summary", text: L(tier.summary) }));

      var price = el("p", { class: "tier__price" });
      var detail = el("p", { class: "tier__detail" });
      var note = L(tier.priceNote);
      if (amount !== null) {
        var from = tier.priceFrom ? { pre: t("sup.fromPrefix"), post: t("sup.fromSuffix") } : { pre: "", post: "" };
        var amountNode = el("span", { class: "tier__amount", text: money(amount, state.currency) + from.post });
        if (from.pre) amountNode.insertBefore(el("span", { class: "tier__from", text: from.pre + " " }), amountNode.firstChild);
        var perNode = el("span", { class: "tier__per", text: t("sup.per." + state.interval) });
        if (lang === "ja") { price.appendChild(perNode); price.appendChild(amountNode); }
        else { price.appendChild(amountNode); price.appendChild(perNode); }
        var inclusive = data.taxInclusive && data.taxInclusive[state.currency];
        if (inclusive && typeof inclusive.rate === "number") {
          var gross = Math.round(amount * (1 + inclusive.rate) * (state.currency === "JPY" ? 1 : 100)) / (state.currency === "JPY" ? 1 : 100);
          // An indicative amount keeps its "From" here too (in Japanese, the 〜 suffix).
          price.appendChild(el("span", {
            class: "tier__gross",
            text: (from.pre ? from.pre + " " : "") + L(inclusive.label).split("{amount}").join(money(gross, state.currency) + from.post),
          }));
        }
        // A tier sold by quote has no billing cycle or saving to state: only its note.
        var s = tier.checkout ? saving(tier, state.currency) : null;
        if (tier.checkout && state.interval === "year") {
          var perMonth = amount / 12;
          if (state.currency === "JPY") perMonth = Math.round(perMonth); else perMonth = Math.round(perMonth * 100) / 100;
          var line = amountOf(tier, state.currency, "month") !== null || intervals.indexOf("month") < 0
            ? t("sup.eq", { amount: money(perMonth, state.currency) }) : t("sup.annualLine");
          detail.appendChild(doc.createTextNode(line + " "));
          if (s) detail.appendChild(el("b", { text: t("sup.saveLine", { amount: money(s.amount, state.currency) }) }));
        } else if (tier.checkout) {
          detail.appendChild(doc.createTextNode(t("sup.monthlyLine") + " "));
          if (s && intervals.indexOf("year") >= 0) detail.appendChild(el("b", { text: t("sup.switchLine", { pct: String(s.pct) }) }));
        }
        if (note) detail.appendChild(doc.createTextNode((detail.firstChild ? " " : "") + note));
      } else {
        price.appendChild(el("span", { class: "tier__amount tier__amount--text", text: note || t("sup.contactPrice") }));
      }
      card.appendChild(price);
      card.appendChild(detail);

      if (Array.isArray(tier.highlights) && tier.highlights.length) {
        card.appendChild(el("ul", { class: "tier__list", role: "list" }, tier.highlights.map(function (h) { return el("li", { text: L(h) }); })));
      }

      var cta = el("div", { class: "tier__cta" });
      var errorId = "tier-" + tier.id + "-error";
      var error = el("p", { class: "tier__error", id: errorId, role: "alert" });
      var online = tier.checkout && data.selfServeOpen !== false;
      if (online && amount !== null) {
        var labelText = L(tier.ctaLabel) || t("sup.subscribe");
        var button = el("button", {
          type: "button",
          class: "btn btn--block " + (featured || !anyFeatured ? "btn--primary" : "btn--ghost"),
          "aria-describedby": errorId,
          "data-subscribe": tier.id,
        }, [el("span", { text: labelText })]);
        button.addEventListener("click", function () { subscribe(tier); });
        cta.appendChild(button);
        refs.cards.push({ id: tier.id, button: button, label: labelText, error: error });
      } else if (email) {
        cta.appendChild(el("a", {
          class: "btn btn--block " + (online || featured ? "btn--primary" : "btn--ghost"),
          href: "mailto:" + email + "?subject=" + encodeURIComponent(t("sup.mail.subject", { name: name })),
          text: (!tier.checkout && L(tier.ctaLabel)) || t("sup.contact"),
        }));
      }
      cta.appendChild(error);
      card.appendChild(cta);
      return card;
    }

    // Disable the controls while a checkout is pending and mark the plan it is for.
    function paintPending() {
      $$("fieldset.seg", host).forEach(function (set) { set.disabled = !!pending; });
      (refs.cards || []).forEach(function (card) {
        var mine = !!pending && pending.tier === card.id;
        if (pending) card.button.setAttribute("aria-disabled", "true"); else card.button.removeAttribute("aria-disabled");
        if (mine) card.button.setAttribute("aria-busy", "true"); else card.button.removeAttribute("aria-busy");
        card.button.classList.toggle("is-loading", mine);
        card.button.lastChild.textContent = mine ? t("sup.redirecting") : card.label;
      });
    }
    // Write into the card on the page now: a language change may have rebuilt it.
    function showError(tier, message) {
      var card = (refs.cards || []).filter(function (c) { return c.id === tier.id; })[0];
      if (!card) return;
      while (card.error.firstChild) card.error.removeChild(card.error.firstChild);
      if (!message) return;
      card.error.appendChild(doc.createTextNode(message + " "));
      if (email) {
        card.error.appendChild(el("a", {
          href: "mailto:" + email + "?subject=" + encodeURIComponent(t("sup.mail.subject", { name: L(tier.name) || tier.id })),
          text: email,
        }));
      }
    }
    function subscribe(tier) {
      if (pending) return;
      win.clearTimeout(resetTimer);
      var mine = pending = { tier: tier.id };
      showError(tier, "");
      paintPending();

      var started;
      try {
        var api = win.KasumiCheckout;
        started = api && typeof api.start === "function"
          ? api.start({ tier: tier.id, interval: state.interval, currency: state.currency })
          : Promise.reject(new Error(t("sup.err.generic")));
      } catch (e) {
        started = Promise.reject(e);
      }
      // Only the request that is still current may change the page.
      Promise.resolve(started).then(function () {
        if (pending !== mine) return;
        // The browser is navigating to Stripe; recover if that is cancelled.
        resetTimer = win.setTimeout(function () {
          if (pending === mine) { pending = null; paintPending(); }
        }, 8000);
      }, function (e) {
        if (pending !== mine) return;
        pending = null;
        paintPending();
        showError(tier, (e && e.message) || t("sup.err.generic"));
      });
    }

    function cell(value, featured) {
      var td = el("td", { class: featured ? "is-featured" : null });
      if (value === true) {
        td.appendChild(el("span", { class: "tick", "aria-hidden": "true" }));
        td.appendChild(el("span", { class: "sr-only", text: t("sup.included") }));
      } else if (value === false || value === null || value === undefined || L(value) === "") {
        td.appendChild(el("span", { class: "dash", "aria-hidden": "true" }));
        td.appendChild(el("span", { class: "sr-only", text: t("sup.notIncluded") }));
      } else {
        td.textContent = L(value);
      }
      return td;
    }

    function matrix() {
      if (!Array.isArray(data.matrix) || !data.matrix.length) return null;
      var head = el("tr", null, [el("th", { scope: "col" }, [el("span", { class: "sr-only", text: t("sup.matrix.feature") })])]);
      tiers.forEach(function (tier) {
        head.appendChild(el("th", { scope: "col", class: tier.featured ? "is-featured" : null, text: L(tier.name) || tier.id }));
      });
      var table = el("table", { class: "matrix" }, [el("caption", { class: "sr-only", text: t("sup.matrix.caption") }), el("thead", null, [head])]);
      data.matrix.forEach(function (group) {
        if (!group || !Array.isArray(group.rows)) return;
        var body = el("tbody");
        if (L(group.group)) {
          body.appendChild(el("tr", { class: "matrix__group" }, [el("th", { scope: "rowgroup", colspan: String(tiers.length + 1), text: L(group.group) })]));
        }
        group.rows.forEach(function (row) {
          var tr = el("tr", null, [el("th", { scope: "row", text: L(row.label) })]);
          tiers.forEach(function (tier) { tr.appendChild(cell(row.values ? row.values[tier.id] : undefined, !!tier.featured)); });
          body.appendChild(tr);
        });
        table.appendChild(body);
      });
      var wrap = el("div", { class: "matrix-wrap", role: "region", "aria-label": t("sup.matrix.caption") }, [table]);
      refs.matrixWrap = wrap;
      return wrap;
    }

    function severities() {
      if (!Array.isArray(data.severities) || !data.severities.length) return null;
      return el("div", { class: "sevs" }, data.severities.map(function (sev) {
        return el("div", { class: "sev" }, [
          el("span", { class: "sev__level", text: L(sev.level) }),
          el("h4", { class: "sev__name", text: L(sev.name) }),
          el("p", { text: L(sev.description) }),
        ]);
      }));
    }

    // Prices and the saving badge change with currency and interval.
    function renderBody() {
      var best = bestSaving();
      if (refs.save) {
        refs.save.textContent = best ? t(best.uniform ? "sup.save" : "sup.saveUpTo", { pct: String(best.pct) }) : "";
        refs.save.hidden = !best;
      }
      refs.cards = [];
      var fresh = el("div", { class: "tiers" }, tiers.map(tierCard));
      refs.tiers.parentNode.replaceChild(fresh, refs.tiers);
      refs.tiers = fresh;
      paintPending();
    }

    // Everything else changes only with the language.
    function render() {
      refs = {};
      while (host.firstChild) host.removeChild(host.firstChild);

      var controls = el("div", { class: "plans__controls" });
      if (intervals.length > 1) {
        refs.save = el("span", { class: "seg__save" });
        controls.appendChild(segment("interval", t("sup.interval"), intervals.map(function (v) {
          return { value: v, label: t("sup." + v), extra: v === "year" ? refs.save : null };
        }), state.interval));
      }
      if (currencies.length > 1) {
        controls.appendChild(segment("currency", t("sup.currency"), currencies.map(function (c) {
          var sym = symbol(c);
          return { value: c, label: sym && sym !== c ? c + " " + sym : c };
        }), state.currency));
      }
      if (controls.firstChild) host.appendChild(controls);

      refs.tiers = el("div", { class: "tiers" });
      host.appendChild(refs.tiers);

      if (data.pilot && email) {
        var pilot = data.pilot;
        host.appendChild(el("aside", { class: "pilot" }, [
          el("div", { class: "pilot__text" }, [
            el("h3", { class: "pilot__title", text: L(pilot.title) }),
            el("p", { text: L(pilot.body) }),
          ]),
          el("a", {
            class: "btn btn--ghost pilot__cta",
            href: "mailto:" + email + "?subject=" + encodeURIComponent(L(pilot.subject) || L(pilot.title)),
            text: L(pilot.ctaLabel),
          }),
        ]));
      }

      var notes = el("p", { class: "plans__notes" });
      if (data.selfServeOpen === false) notes.appendChild(el("span", { text: t("sup.closed") }));
      if (L(data.taxNote)) notes.appendChild(el("span", { text: L(data.taxNote) }));
      notes.appendChild(el("span", null, [
        el("a", { href: "/legal/support-terms", text: t("sup.terms") }),
        doc.createTextNode(" · "),
        el("a", { href: "/legal/tokushoho", text: t("sup.legal") }),
      ]));
      if (typeof data.portalUrl === "string" && /^https?:\/\//i.test(data.portalUrl)) {
        notes.appendChild(el("a", { href: data.portalUrl, rel: "noopener", text: t("sup.portal") }));
      }
      if (email) {
        notes.appendChild(el("span", null, [t("sup.questions") + " ", el("a", { href: "mailto:" + email, text: email })]));
      }
      if (notes.firstChild) host.appendChild(notes);

      var table = matrix();
      if (table) {
        host.appendChild(el("h3", { class: "plans__h", text: t("sup.compare") }));
        host.appendChild(table);
      }
      var sevs = severities();
      if (sevs) {
        host.appendChild(el("h3", { class: "plans__h", text: t("sup.sev") }));
        host.appendChild(sevs);
        if (L(data.responseNote)) host.appendChild(el("p", { class: "plans__fine", text: L(data.responseNote) }));
      }
      renderBody();
      fitMatrix();
    }

    // The comparison table becomes a keyboard-scrollable region only when it overflows.
    function fitMatrix() {
      var wrap = refs.matrixWrap;
      if (!wrap) return;
      if (wrap.scrollWidth > wrap.clientWidth + 1) wrap.setAttribute("tabindex", "0");
      else wrap.removeAttribute("tabindex");
    }
    if ("ResizeObserver" in win) new ResizeObserver(fitMatrix).observe(host);
    // Back from Stripe out of the page cache: that checkout is over.
    win.addEventListener("pageshow", function (event) {
      if (!event.persisted) return;
      win.clearTimeout(resetTimer);
      pending = null;
      render();
    });

    langListeners.push(render);
    render();
  }

  // Thank-you page: show the billing-portal link once plans.js names one.
  function initPortalLinks() {
    var url = win.KASUMI_PLANS && win.KASUMI_PLANS.portalUrl;
    if (typeof url !== "string" || url.indexOf("https://billing.stripe.com/") !== 0) return;
    $$("[data-portal-link]").forEach(function (a) { a.setAttribute("href", url); a.setAttribute("rel", "noopener"); a.hidden = false; });
  }

  // ───────────── Start ─────────────
  initLang();
  initPortalLinks();
  initHeader();
  initPlans();
  initScene();
  initBands();
  initReveal();
  initTilt();
  initRetry();
  initCopy();
  initScrollers();

  // The pinned hero and the rendered plans change the page height after the
  // browser's own anchor jump, so a return to /ja#support (Stripe's cancel
  // URL) would land short. Jump again once layout has settled.
  function jumpToHash() {
    var id = win.location.hash.slice(1);
    var target = id && /^[A-Za-z][\w-]*$/.test(id) ? doc.getElementById(id) : null;
    if (!target) return;
    // scrollIntoView honours the target's scroll-margin-top (the fixed header).
    try { target.scrollIntoView({ block: "start", behavior: "instant" }); } catch (e) { target.scrollIntoView(true); }
  }
  if (win.location.hash) {
    if (doc.readyState === "complete") win.setTimeout(jumpToHash, 0);
    else win.addEventListener("load", function () { win.setTimeout(jumpToHash, 0); }, { once: true });
  }

  win.KasumiSite = {
    getLang: function () { return lang; },
    setLang: function (next) { setLang(next, true); },
  };
})();
