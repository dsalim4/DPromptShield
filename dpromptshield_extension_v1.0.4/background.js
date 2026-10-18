const RELAY_ORIGIN = "http://localhost:4000"; // Replace with the deployed Cloud Run hostname before loading the extension
const LOG_URL    = `${RELAY_ORIGIN}/api/pii-logs`;
const URLS_URL   = `${RELAY_ORIGIN}/api/monitored-urls?enabledOnly=true`;
const RULES_URL  = `${RELAY_ORIGIN}/api/pii-rules?enabledOnly=true`;
const STREAM_URL = `${RELAY_ORIGIN}/api/policy-stream`;
const MAX_LOGS   = 500;
const CONTENT_SCRIPT_ID = "aipii-guard-main";
console.info("DPromptShield MV3 service worker ready (extension 1.0.4)");

// Register the request handler before starting background initialization. MV3
// wakes this worker for runtime messages; the listener must exist synchronously
// during worker evaluation.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "CHECK_WHITELIST_SYNC") {
    let responded = false;
    const reply = (payload) => {
      if (responded) return;
      responded = true;
      try { sendResponse(payload); } catch (err) {
        console.debug("aipii-guard: policy response recipient disconnected:", err.message);
      }
    };
    (async () => {
      const result = await syncRules();
      if (result.ok) return reply(result);
      try {
        const cached = await chrome.storage.local.get({ __piiRules: [] });
        reply({ ok: false, rules: cached.__piiRules || [], whitelist: [] });
      } catch (err) {
        console.error("aipii-guard: unable to read cached policy after sync failure:", err.message);
        reply({ ok: false, rules: [], whitelist: [] });
      }
    })().catch((err) => {
      console.error("aipii-guard: CHECK_WHITELIST_SYNC handler failed:", err.message);
      reply({ ok: false, rules: [], whitelist: [] });
    });
    return true;
  }
  if (msg?.type === "GET_WHITELIST") {
    chrome.storage.local.get({ __whitelist: [] }, (d) => sendResponse({ whitelist: d.__whitelist || [] }));
    return true;
  }
  if (msg?.type !== "LOG") return;
  handleLog(msg.entry);
});

// Best-effort metadata only; this is not required for message handling.
chrome.storage.local.set({ __relayOrigin: RELAY_ORIGIN }).catch((err) => {
  console.debug("aipii-guard: relay origin metadata was not persisted:", err.message);
});


// ---------------------------------------------------------------------------
// Device identity — no local agent, and no client-side IP self-reporting
// either (an earlier version of this tried chrome.system.network, which
// turned out to be a Chrome Apps-only API, not available to regular
// extensions — see README for the correction). The relay server now reads
// the real client IP directly off the incoming connection when this
// extension POSTs an incident (see server.js: getClientIp()). Nothing
// extra is needed here for that to work, on any browser.
//
// Enterprise-managed extras (deviceLabel/employeeId) still come from
// chrome.storage.managed, independent of all of the above — set via GPO/
// Intune policy if you want them, skip entirely if you don't.
// ---------------------------------------------------------------------------

async function getIdentity() {
  const managed = await chrome.storage.managed.get(["deviceLabel", "employeeId"]).catch(() => ({}));
  return {
    deviceLabel: managed.deviceLabel || null,
    employeeId:  managed.employeeId  || null,
  };
}

// ---------------------------------------------------------------------------
// PII rule sync — same console-controlled pattern as monitored URLs.
// content.js reads these from chrome.storage.local (set here) rather than
// having its own hardcoded detector list. Pattern/flags come straight from
// the server; validator/keyMode are just labels content.js uses to pick
// from its own small fixed set of real validation functions.
// ---------------------------------------------------------------------------

async function syncRules() {
  try {
    const res = await fetch(RULES_URL, { signal: AbortSignal.timeout(8000), cache: "no-store" });
    if (!res.ok) throw new Error(`status ${res.status}`);
    const data = await res.json();
    if (!Array.isArray(data.rules) || !Array.isArray(data.whitelist)) {
      throw new Error("policy response has an invalid schema");
    }
    const syncedAt = Date.now();
    await chrome.storage.local.set({
      __piiRules: data.rules,
      __whitelist: data.whitelist,   // IP-filtered by server; content.js checks URL+type
      __policySyncedAt: syncedAt,
    });
    return { ok: true, rules: data.rules, whitelist: data.whitelist, syncedAt };
  } catch (err) {
    console.warn("aipii-guard: policy sync failed; cached rules are not authoritative:", err.message);
    return { ok: false };
  }
}


// ---------------------------------------------------------------------------
// Monitored-site sync — console-controlled, nothing in the extension can
// override it (no options page, no popup control).
// ---------------------------------------------------------------------------

function expandPatterns(rawPatterns) {
  const expanded = new Set();
  for (const pat of rawPatterns || []) {
    if (!pat) continue;
    expanded.add(pat);

    const m = pat.match(/^https?:\/\/([^/]+)(.*)$/i);
    if (!m) continue;
    const host = m[1].toLowerCase();

    // Ensure the full host wildcard is included
    expanded.add(`https://${host}/*`);

    if (!host.startsWith("*.")) {
      if (host.startsWith("www.")) {
        const root = host.slice(4);
        expanded.add(`https://${root}/*`);
        expanded.add(`https://*.${root}/*`);
      } else {
        expanded.add(`https://*.${host}/*`);
      }
    }
  }
  return [...expanded];
}

async function syncMonitoredUrls() {
  let patterns = [];
  try {
    const res = await fetch(URLS_URL);
    if (!res.ok) throw new Error(`status ${res.status}`);
    const data = await res.json();
    const rawPatterns = (data.urls || []).map((u) => u.Pattern).filter(Boolean);
    patterns = expandPatterns(rawPatterns);
  } catch (err) {
    console.warn("aipii-guard: could not reach console for monitored URLs, keeping previous list:", err.message);
    return;
  }

  try {
    const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [CONTENT_SCRIPT_ID] });
    if (existing.length) {
      await chrome.scripting.unregisterContentScripts({ ids: [CONTENT_SCRIPT_ID] });
    }
    if (patterns.length) {
      await chrome.scripting.registerContentScripts([
        { id: CONTENT_SCRIPT_ID, matches: patterns, js: ["content.js"], runAt: "document_start" },
      ]);
    }
    chrome.storage.local.set({ __monitoredUrls: patterns });

    // registerContentScripts only covers FUTURE navigations. Inject directly
    // into any tabs that are already open and now match the updated policy,
    // so users don't have to manually reload the page after a policy change.
    await injectIntoOpenTabs(patterns);
  } catch (err) {
    console.error("aipii-guard: failed to register content scripts:", err.message);
  }
}


// Query open tabs whose URL matches any of the monitored patterns and inject
// content.js into them immediately. Guards against double-injection by marking
// tabs with a flag on first injection (content.js is wrapped in an IIFE and
// only sets up its listeners once, so double-execution is harmless but noisy).
async function injectIntoOpenTabs(patterns) {
  if (!patterns.length) return;
  try {
    // chrome.tabs.query accepts an array of match patterns when 'tabs'
    // permission is present (or host_permissions covers the URL).
    const tabs = await chrome.tabs.query({ url: patterns });
    let injected = 0;
    for (const tab of tabs) {
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id, allFrames: false },
          files:  ["content.js"],
        });
        injected++;
      } catch (err) {
        // Tab may be a protected page (chrome://, PDF, etc.) — silently skip.
        console.warn(`aipii-guard: skipped injection into tab ${tab.id} (${tab.url}):`, err.message);
      }
    }
    if (injected) {
      console.log(`aipii-guard: injected content.js into ${injected} already-open tab(s)`);
    }
  } catch (err) {
    console.warn("aipii-guard: injectIntoOpenTabs failed:", err.message);
  }
}


// ---------------------------------------------------------------------------
// Policy-push via Server-Sent Events (SSE)
//
// The server broadcasts a "policy-change" event whenever rules or monitored
// URLs are modified via the dashboard. The extension listens here so it
// can apply changes immediately instead of waiting for the hourly alarm.
//
// fetch()-based SSE is used because MV3 service workers cannot keep a
// persistent EventSource alive across suspension. We re-open the stream
// after each disconnection with exponential backoff.
// ---------------------------------------------------------------------------

const SSE_RECONNECT_MIN_MS = 5_000;  // initial backoff: 5 s
const SSE_RECONNECT_MAX_MS = 60_000; // cap: 60 s

let _sseReconnectDelay = SSE_RECONNECT_MIN_MS;
let _sseAbort = null;

async function listenPolicyStream() {
  // Cancel any previous open stream before opening a new one.
  if (_sseAbort) { _sseAbort.abort(); _sseAbort = null; }

  const controller = new AbortController();
  _sseAbort = controller;

  try {
    const res = await fetch(STREAM_URL, {
      signal: controller.signal,
      headers: { Accept: "text/event-stream", "Cache-Control": "no-cache" },
    });

    if (!res.ok || !res.body) throw new Error(`SSE open failed: ${res.status}`);

    _sseReconnectDelay = SSE_RECONNECT_MIN_MS; // reset backoff on successful connect
    console.log("aipii-guard: connected to policy-stream");

    const reader  = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buf += decoder.decode(value, { stream: true });

      // SSE frames are separated by double newlines.
      const frames = buf.split(/\n\n/);
      buf = frames.pop(); // last incomplete frame stays in buffer

      for (const frame of frames) {
        const eventLine = frame.split("\n").find((l) => l.startsWith("event:"));
        const dataLine  = frame.split("\n").find((l) => l.startsWith("data:"));
        const eventName = eventLine ? eventLine.slice(6).trim() : "message";
        const data      = dataLine  ? dataLine.slice(5).trim()  : "";

        if (eventName === "policy-change") {
          console.log("aipii-guard: policy-change push received —", data, "— syncing immediately");
          await Promise.all([syncRules(), syncMonitoredUrls()]);
        }
        // "ping" frames are silently ignored — they only keep the TCP connection alive.
      }
    }
  } catch (err) {
    if (err.name === "AbortError") return; // intentional close, do not reconnect
    console.warn(
      "aipii-guard: policy-stream error, reconnecting in",
      _sseReconnectDelay,
      "ms:", err.message
    );
  }

  // Exponential backoff before reconnect.
  await new Promise((r) => setTimeout(r, _sseReconnectDelay));
  _sseReconnectDelay = Math.min(_sseReconnectDelay * 2, SSE_RECONNECT_MAX_MS);
  listenPolicyStream(); // tail-recursive reconnect (does not block the service worker)
}

// ---------------------------------------------------------------------------
// Incident logging
// ---------------------------------------------------------------------------

async function handleLog(rawEntry) {
  const identity = await getIdentity();
  const entry = { ...rawEntry, ...identity, synced: false };

  chrome.storage.local.get({ logs: [] }, ({ logs }) => {
    logs.unshift(entry);
    if (logs.length > MAX_LOGS) logs.length = MAX_LOGS;
    chrome.storage.local.set({ logs }, updateBadge);
  });

  forwardToRelay(entry);
}

async function forwardToRelay(entry) {
  try {
    const res = await fetch(LOG_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(entry),
    });
    if (res.ok) markSynced(entry.ts);
  } catch (_) {
    // relay unreachable — stays synced:false, retried by the alarm below
  }
}

function markSynced(ts) {
  chrome.storage.local.get({ logs: [] }, ({ logs }) => {
    const i = logs.findIndex((l) => l.ts === ts);
    if (i !== -1) {
      logs[i].synced = true;
      chrome.storage.local.set({ logs });
    }
  });
}

async function retryUnsynced() {
  chrome.storage.local.get({ logs: [] }, async ({ logs }) => {
    const pending = logs.filter((l) => !l.synced);
    for (const entry of pending) await forwardToRelay(entry);
  });
}

function updateBadge() {
  chrome.storage.local.get({ logs: [] }, ({ logs }) => {
    chrome.action.setBadgeBackgroundColor({ color: "#d93025" });
    chrome.action.setBadgeText({ text: logs.length ? String(logs.length) : "" });
  });
}

// ---------------------------------------------------------------------------
// Scheduling — hourly alarms are a belt-and-suspenders fallback; the SSE
// stream will push changes immediately under normal conditions.
// retry-sync stays at 1 min so offline logs don't queue too long.
// ---------------------------------------------------------------------------

chrome.alarms.create("retry-sync", { periodInMinutes: 1 });
chrome.alarms.create("url-sync",   { periodInMinutes: 30 });
chrome.alarms.create("rule-sync",  { periodInMinutes: 30 });

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === "retry-sync") retryUnsynced();
  if (a.name === "url-sync")   syncMonitoredUrls();
  if (a.name === "rule-sync")  syncRules();
});

chrome.storage.onChanged.addListener((c) => { if (c.logs) updateBadge(); });

chrome.runtime.onStartup.addListener(() => {
  updateBadge();
  syncMonitoredUrls();
  syncRules();
  listenPolicyStream();
});

chrome.runtime.onInstalled.addListener(() => {
  updateBadge();
  syncMonitoredUrls();
  syncRules();
  listenPolicyStream();
});
