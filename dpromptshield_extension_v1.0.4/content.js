(() => {
  if (window.__aipii_guard_injected) return;
  window.__aipii_guard_injected = true;

  // ---------- Validators: a small FIXED whitelist, not arbitrary server
  // code. The server/dashboard can ship new regex PATTERNS freely, but a
  // genuinely new validation algorithm (beyond these three) requires an
  // actual content.js code change — that's a deliberate security boundary,
  // not an oversight. See README.
  const digits = (s) => s.replace(/\D/g, "");

  function isValidNik(d) {
    if (d.length !== 16) return false;
    const prov = +d.slice(0, 2);
    let day = +d.slice(6, 8);
    const month = +d.slice(8, 10);
    if (day > 40) day -= 40; // female encoding
    return prov >= 11 && prov <= 96 && day >= 1 && day <= 31 && month >= 1 && month <= 12;
  }

  function luhn(d) {
    if (d.length < 13 || d.length > 19) return false;
    let sum = 0, alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = +d[i];
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  }

  const VALIDATORS = {
    none: () => true,
    luhn: (v) => luhn(digits(v)),
    nik: (v) => isValidNik(digits(v)),
  };

  const KEY_FNS = {
    digits: digits,
    text: (v) => v.toLowerCase().trim(),
  };

  // ---------- Rules: fetched from the console via background.js, cached
  // here and kept live via chrome.storage.onChanged so an already-open tab
  // picks up a rule change without needing a reload.
  let DETECTORS = [];
  let WHITELIST = []; // entries: { UrlPattern: string|null, RuleType: string|null }
  let policyReady = false; // only an authoritative sync can enable submissions
  let extensionContextInvalid = false;
  let syncInFlight = false;
  let failedSyncs = 0;
  let retryTimer = null;
  let refreshTimer = null;

  function invalidateExtensionContext() {
    if (extensionContextInvalid) return;
    extensionContextInvalid = true;
    policyReady = false;
    if (retryTimer) clearTimeout(retryTimer);
    if (refreshTimer) clearInterval(refreshTimer);
    retryTimer = refreshTimer = null;
    // Do not call extension APIs again from an isolated world invalidated by
    // reload. DOM submission guards remain installed and fail closed.
  }

  function contextIsAlive() {
    if (extensionContextInvalid) return false;
    try {
      if (chrome?.runtime?.id) return true;
    } catch (_) { /* extension reload invalidated this context */ }
    invalidateExtensionContext();
    return false;
  }

  function compileRules(rawRules) {
    const compiled = [];
    for (const rule of rawRules || []) {
      try {
        const flags = (rule.Flags || "g").includes("g") ? (rule.Flags || "g") : (rule.Flags || "") + "g";
        const re = new RegExp(rule.Pattern, flags); // matchAll() requires the 'g' flag — always ensured here
        const ok = VALIDATORS[rule.Validator] || VALIDATORS.none;
        const key = KEY_FNS[rule.KeyMode] || KEY_FNS.digits;
        const action = (rule.Action || rule.action || rule.Mode || rule.mode || "block").toLowerCase();
        compiled.push({ type: rule.Type, re, ok, key, action });
      } catch (err) {
        console.warn(`aipii-guard: invalid policy rule "${rule?.Type || "unknown"}":`, err.message);
      }
    }
    return compiled;
  }

  function matchUrl(pattern, href) {
    if (!pattern) return true;
    let p = pattern.trim();
    if (!/^https?:\/\//i.test(p) && !p.startsWith("*://")) {
      p = "*://" + p;
    }
    if (!p.includes("/", 8)) {
      p = p + "/*";
    }
    try {
      const rx = new RegExp("^" + p.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$", "i");
      if (rx.test(href)) return true;
    } catch (_) { }
    try {
      const host = new URL(href).hostname.toLowerCase();
      const cleanP = pattern.replace(/^https?:\/\//i, "").replace(/[\/*].*$/, "").toLowerCase();
      return host === cleanP || host.endsWith("." + cleanP);
    } catch (_) {
      return false;
    }
  }

  // Check if the current page + pii type is whitelisted for this device.
  // The server already filtered the whitelist entries to this device's IP.
  function isWhitelisted(piiType) {
    if (!policyReady || !Array.isArray(WHITELIST) || WHITELIST.length === 0) return false;
    const href = location.href;
    for (const entry of WHITELIST) {
      const urlOk = !entry.UrlPattern || matchUrl(entry.UrlPattern, href);
      const typeOk = !entry.RuleType || entry.RuleType.toUpperCase() === (piiType || "").toUpperCase();
      if (urlOk && typeOk) return true;
    }
    return false;
  }

  async function applyServerPolicy(data) {
    if (!contextIsAlive() || !Array.isArray(data?.rules) || !Array.isArray(data?.whitelist)) return false;
    const compiled = compileRules(data.rules);
    if (compiled.length !== data.rules.length) {
      console.error("aipii-guard: policy rejected because one or more detection rules are invalid");
      return false;
    }
    DETECTORS = compiled;
    WHITELIST = data.whitelist;
    try {
      await chrome.storage.local.set({
        __piiRules: data.rules,
        __whitelist: data.whitelist,
        __policySyncedAt: Date.now(),
      });
    } catch (err) {
      if (!contextIsAlive()) return false;
      console.error("aipii-guard: refusing to trust policy because the cache could not be updated:", err.message);
      return false;
    }
    policyReady = true;
    failedSyncs = 0;
    return true;
  }

  function requestWorkerPolicy() {
    return new Promise((resolve) => {
      if (!contextIsAlive()) return resolve(null);
      let settled = false;
      const timeout = setTimeout(() => finish(null), 10_000);
      const finish = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        resolve(value);
      };
      try {
        const maybePromise = chrome.runtime.sendMessage({ type: "CHECK_WHITELIST_SYNC" }, (response) => {
          let lastError;
          try { lastError = chrome.runtime.lastError; } catch (_) { /* reload path */ }
          if (lastError) {
            if (contextIsAlive()) console.warn("aipii-guard: service worker did not answer policy sync:", lastError.message);
            return finish(null);
          }
          finish(response || null);
        });
        // Newer Chrome versions can expose both callback and Promise forms.
        // Observe both to prevent an unhandled rejection during extension reload.
        if (maybePromise && typeof maybePromise.then === "function") {
          maybePromise.then(finish, (err) => {
            if (contextIsAlive()) console.warn("aipii-guard: policy message failed:", err?.message || "unknown error");
            finish(null);
          });
        }
      } catch (err) {
        if (contextIsAlive()) console.warn("aipii-guard: service worker unavailable:", err?.message || "unknown error");
        finish(null);
      }
    });
  }

  async function fetchPolicyNow() {
    if (syncInFlight || !contextIsAlive()) return;
    syncInFlight = true;
    policyReady = false;
    let applied = false;
    try {
      // Content scripts run in the page's origin and are subject to its CORS
      // policy. The MV3 service worker owns relay fetches using host_permissions.
      const response = await requestWorkerPolicy();
      if (!contextIsAlive()) return;
      if (response?.ok !== true) throw new Error("service worker could not provide a fresh policy");
      applied = await applyServerPolicy(response);
      if (!applied) throw new Error("service worker returned an invalid policy");
    } catch (err) {
      if (!contextIsAlive()) return;
      console.warn("aipii-guard: service-worker policy sync failed:", err?.message || "unknown error");
    }

    if (!contextIsAlive()) return;
    if (applied) {
      failedSyncs = 0;
      if (!refreshTimer) refreshTimer = setInterval(fetchPolicyNow, 30_000);
    } else {
      policyReady = false;
      if (refreshTimer) clearInterval(refreshTimer);
      refreshTimer = null;
      failedSyncs++;
      const delays = [2_000, 8_000, 30_000];
      if (failedSyncs <= delays.length && !retryTimer) {
        retryTimer = setTimeout(() => {
          retryTimer = null;
          fetchPolicyNow();
        }, delays[failedSyncs - 1]);
      } else {
        console.error("aipii-guard: policy unavailable after bounded retries; submissions remain blocked");
      }
    }
    syncInFlight = false;
  }

  function onStorageChanged(changes, area) {
    if (area !== "local" || !contextIsAlive()) return;
    if (changes.__piiRules) {
      const compiled = compileRules(changes.__piiRules.newValue);
      if (compiled.length !== (changes.__piiRules.newValue || []).length) policyReady = false;
      else DETECTORS = compiled;
    }
    if (changes.__whitelist) WHITELIST = changes.__whitelist.newValue || [];
    if (changes.__policySyncedAt) {
      policyReady = Date.now() - Number(changes.__policySyncedAt.newValue || 0) <= 60_000;
    }
  }
  chrome.storage.onChanged.addListener(onStorageChanged);

  function onRecoverySignal() {
    if (contextIsAlive() && !policyReady && !syncInFlight) {
      failedSyncs = 0;
      fetchPolicyNow();
    }
  }
  window.addEventListener("online", onRecoverySignal);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") onRecoverySignal();
  });
  fetchPolicyNow();



  // ---------- PII scanning ----------

  function mask(v) {
    const c = v.replace(/\s/g, "");
    return c.length <= 6 ? "***" : c.slice(0, 2) + "*".repeat(c.length - 4) + c.slice(-2);
  }

  function scan(text) {
    if (!text || typeof text !== "string") return [];
    const found = [];
    const taken = [];
    for (const det of DETECTORS) {
      for (const m of text.matchAll(det.re)) {
        const s = m.index, e = s + m[0].length;
        if (taken.some(([a, b]) => s < b && e > a)) continue;
        if (!det.ok(m[0])) continue;
        if (isWhitelisted(det.type)) continue;   // skip whitelisted type on this page
        taken.push([s, e]);
        found.push({ type: det.type, masked: mask(m[0]), action: det.action || "block" });
      }
    }
    return found;
  }


  // ---------- DOM helpers ----------
  const EDITOR_SEL = 'textarea, input[type="text"], [contenteditable]:not([contenteditable="false"]), [role="textbox"], .ProseMirror, [data-slate-editor="true"]';
  let lastEditor = null;

  const editorOf = (el) => {
    if (!el) return null;
    if (el.matches && el.matches(EDITOR_SEL)) return el;
    return el.closest ? el.closest(EDITOR_SEL) : null;
  };

  const textOf = (el) => {
    if (!el) return "";
    if (el.value !== undefined) return el.value;
    return el.innerText ?? el.textContent ?? "";
  };

  function currentEditor() {
    if (lastEditor && document.contains(lastEditor)) return lastEditor;
    const active = document.activeElement;
    if (active && editorOf(active)) return editorOf(active);
    const editors = [...document.querySelectorAll(EDITOR_SEL)];
    return editors.find((e) => {
      const rect = e.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    }) || editors[0] || null;
  }

  function isSendButton(btn) {
    if (!btn) return false;
    if (btn.type === "submit") return true;
    const label = `${btn.getAttribute("aria-label") || ""} ${btn.getAttribute("data-testid") || ""} ${btn.title || ""} ${btn.className || ""} ${btn.id || ""} ${btn.innerText || ""}`;
    return /send|submit|kirim|fasong|发送|enviar|post|chat-input-send|chat-send/i.test(label);
  }

  // ---------- Toast notification ----------
  function toast(msg) {
    let t = document.getElementById("__aipii_guard_toast");
    if (!t) {
      t = document.createElement("div");
      t.id = "__aipii_guard_toast";
      Object.assign(t.style, {
        position: "fixed",
        bottom: "24px",
        left: "50%",
        transform: "translateX(-50%)",
        background: "#d93025",
        color: "#fff",
        padding: "12px 18px",
        borderRadius: "8px",
        font: "14px system-ui, sans-serif",
        zIndex: 2147483647,
        boxShadow: "0 4px 16px rgba(0,0,0,.3)",
        maxWidth: "80vw",
      });
      document.documentElement.appendChild(t);
    }
    t.textContent = msg;
    t.style.display = "block";
    clearTimeout(t.__h);
    t.__h = setTimeout(() => (t.style.display = "none"), 5000);
  }

  // ---------- Log helper ----------
  function logIncident(findings, action, extraText) {
    const types = [...new Set(findings.map((h) => h.type))];
    if (!contextIsAlive()) return types;
    try {
      const pending = chrome.runtime.sendMessage({
        type: "LOG",
        entry: {
          ts: new Date().toISOString(),
          site: location.hostname,
          action,
          findings,
          promptLength: (extraText || "").length,
        },
      }, () => {
        try {
          const err = chrome.runtime.lastError;
          if (err && contextIsAlive()) console.warn("aipii-guard: incident could not be sent:", err.message);
        } catch (_) { invalidateExtensionContext(); }
      });
      if (pending && typeof pending.catch === "function") {
        pending.catch((err) => {
          if (contextIsAlive()) console.warn("aipii-guard: incident message rejected:", err?.message || "unknown error");
        });
      }
    } catch (err) {
      if (contextIsAlive()) console.warn("aipii-guard: incident message failed:", err?.message || "unknown error");
    }
    return types;
  }

  // ---------- Paste interception — block at paste time ----------
  document.addEventListener("paste", (e) => {
    const ed = editorOf(e.target) || currentEditor();
    if (!ed) return;
    const text = e.clipboardData?.getData("text/plain") || "";
    if (!text) return;

    const hits = scan(text);
    if (!hits.length) return;

    const blockingHits = hits.filter((h) => (h.action || "block") === "block");
    if (!blockingHits.length) {
      // All detected rules are set to "monitor" -> allow pasting
      return;
    }

    e.preventDefault();
    e.stopImmediatePropagation();
    e.stopPropagation();

    const types = logIncident(blockingHits, "PASTE_BLOCKED", text);
    toast(`Blocked paste: contains PII (${types.join(", ")}). Remove the sensitive data before pasting.`);
  }, true);

  // ---------- Drop interception — same logic as paste ----------
  document.addEventListener("drop", (e) => {
    const ed = editorOf(e.target) || currentEditor();
    if (!ed) return;
    const text = e.dataTransfer?.getData("text/plain") || "";
    if (!text) return;

    const hits = scan(text);
    if (!hits.length) return;

    const blockingHits = hits.filter((h) => (h.action || "block") === "block");
    if (!blockingHits.length) {
      // All detected rules are set to "monitor" -> allow dropping
      return;
    }

    e.preventDefault();
    e.stopImmediatePropagation();
    e.stopPropagation();

    const types = logIncident(blockingHits, "DROP_BLOCKED", text);
    toast(`Blocked drop: contains PII (${types.join(", ")}). Remove the sensitive data first.`);
  }, true);

  // ---------- Track last active editor (for send-button guard) ----------
  document.addEventListener("input", (e) => {
    const ed = editorOf(e.target);
    if (!ed) return;
    lastEditor = ed;
  }, true);

  document.addEventListener("focusin", (e) => {
    const ed = editorOf(e.target);
    if (ed) lastEditor = ed;
  }, true);

  // ---------- Send / submit guard ----------
  let lastMonitoredLog = { text: "", time: 0 };

  function guard(e) {
    const ed = currentEditor();
    if (!ed) return false;
    if (!contextIsAlive()) policyReady = false;
    if (!policyReady) {
      e.preventDefault();
      e.stopImmediatePropagation();
      e.stopPropagation();
      toast("Policy could not be verified. Sending is blocked; restore the extension connection and reload this tab.");
      return true;
    }
    const text = textOf(ed);
    const hits = scan(text);
    if (!hits.length) return false;

    const blockingHits = hits.filter((h) => (h.action || "block") === "block");
    if (blockingHits.length > 0) {
      // Block prompt send, show alert popup, and log as BLOCKED
      e.preventDefault();
      e.stopImmediatePropagation();
      e.stopPropagation();

      const types = logIncident(hits, "BLOCKED", text);
      toast(`Blocked: prompt contains PII (${types.join(", ")}). This prompt is monitored and blocked by CISO Office Group, consider not trying to share personal information.`);
      return true;
    }

    // All matching rules are set to "monitor" only.
    // User CAN still send the prompt, but it gets monitored in the log!
    const now = Date.now();
    if (lastMonitoredLog.text !== text || now - lastMonitoredLog.time > 1500) {
      lastMonitoredLog = { text, time: now };
      logIncident(hits, "MONITORED", text);
    }
    return false;
  }

  window.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
    const ed = editorOf(e.target) || currentEditor();
    if (!ed) return;
    guard(e);
  }, true);

  const onClick = (e) => {
    const btn = e.target.closest && e.target.closest("button, [role=button], .send-btn, [class*='send'], [class*='submit']");
    if (isSendButton(btn)) guard(e);
  };
  window.addEventListener("click", onClick, true);
  window.addEventListener("mousedown", (e) => {
    const btn = e.target.closest && e.target.closest("button, [role=button], .send-btn, [class*='send'], [class*='submit']");
    if (isSendButton(btn)) guard(e);
  }, true);
  window.addEventListener("submit", (e) => guard(e), true);
})();
