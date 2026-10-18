"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const contentScript = fs.readFileSync(path.join(__dirname, "..", "content.js"), "utf8");
const backgroundScript = fs.readFileSync(path.join(__dirname, "..", "background.js"), "utf8");

function createContentContext({ workerPolicy = { ok: false, rules: [], whitelist: [] } }) {
  const listeners = new Map();
  const storageListeners = [];
  const editor = {
    value: "SYNTHETIC_SECRET",
    matches: () => true,
    getBoundingClientRect: () => ({ width: 300, height: 40 }),
  };
  const toast = { style: {}, textContent: "" };
  let workerMessages = 0;
  const chrome = {
    runtime: {
      id: "test-extension-id",
      sendMessage(message, callback) {
        workerMessages++;
        if (message.type === "CHECK_WHITELIST_SYNC" && callback) callback(workerPolicy);
      },
    },
    storage: {
      local: { set: async () => {} },
      onChanged: { addListener: (fn) => storageListeners.push(fn) },
    },
  };
  const document = {
    activeElement: editor,
    visibilityState: "visible",
    documentElement: { appendChild() {} },
    addEventListener(type, fn) {
      const entry = listeners.get(`document:${type}`) || [];
      entry.push(fn);
      listeners.set(`document:${type}`, entry);
    },
    contains: () => true,
    querySelectorAll: () => [editor],
    getElementById: () => toast,
    createElement: () => ({ style: {}, textContent: "" }),
  };
  const window = {
    __aipii_guard_injected: false,
    addEventListener(type, fn) {
      const entry = listeners.get(`window:${type}`) || [];
      entry.push(fn);
      listeners.set(`window:${type}`, entry);
    },
  };
  const sandbox = {
    window, document, chrome, location: { href: "https://chatgpt.com/", hostname: "chatgpt.com" },
    fetch: () => { throw new Error("content script must not fetch the relay directly"); },
    AbortSignal,
    URL,
    console: { warn() {}, error() {}, log() {} },
    setTimeout: () => 1,
    clearTimeout() {},
    setInterval: () => 2,
    clearInterval() {},
  };
  vm.runInNewContext(contentScript, sandbox, { filename: "content.js" });
  return { listeners, chrome, toast, get workerMessages() { return workerMessages; }, editor };
}

function submitKey(context) {
  let prevented = false;
  const event = {
    key: "Enter", shiftKey: false, isComposing: false, target: context.editor,
    preventDefault() { prevented = true; },
    stopImmediatePropagation() {},
    stopPropagation() {},
  };
  for (const listener of context.listeners.get("window:keydown") || []) listener(event);
  return prevented;
}

test("a policy sync outage blocks prompt submission rather than trusting cached policy", () => {
  const context = createContentContext({});
  assert.equal(submitKey(context), true);
  assert.match(context.toast.textContent, /Policy could not be verified/);
});

test("an invalidated extension context blocks locally and sends no more extension messages", async () => {
  const context = createContentContext({
    workerPolicy: {
      ok: true,
        rules: [{ Type: "SYNTH", Pattern: "SYNTHETIC_SECRET", Flags: "g", Validator: "none", Mode: "monitor" }],
        whitelist: [],
      },
  });
  await new Promise((resolve) => setImmediate(resolve));
  const messagesBeforeInvalidation = context.workerMessages;
  context.chrome.runtime.id = undefined; // simulate Chrome extension reload
  assert.equal(submitKey(context), true);
  assert.equal(context.workerMessages, messagesBeforeInvalidation);
});

test("CHECK_WHITELIST_SYNC responds with the fresh server whitelist and rules", async () => {
  let onMessage;
  const state = {};
  const rules = [{ Type: "SYNTH", Pattern: "SYNTHETIC_SECRET" }];
  const whitelist = [{ UrlPattern: "https://chatgpt.com/*", RuleType: "SYNTH" }];
  const chrome = {
    storage: {
      local: {
        async set(values) { Object.assign(state, values); },
        async get(defaults) { return { ...defaults, ...state }; },
      },
      onChanged: { addListener() {} },
    },
    runtime: {
      onMessage: { addListener(fn) { onMessage = fn; } },
      onStartup: { addListener() {} },
      onInstalled: { addListener() {} },
    },
    alarms: { create() {}, onAlarm: { addListener() {} } },
    action: { setBadgeBackgroundColor() {}, setBadgeText() {} },
  };
  const sandbox = {
    chrome,
    fetch: async () => ({ ok: true, json: async () => ({ rules, whitelist }) }),
    AbortSignal,
    console: { warn() {}, error() {}, debug() {}, log() {}, info() {} },
    setTimeout,
  };
  vm.runInNewContext(backgroundScript, sandbox, { filename: "background.js" });
  const response = await new Promise((resolve) => {
    const keepChannelOpen = onMessage({ type: "CHECK_WHITELIST_SYNC" }, {}, resolve);
    assert.equal(keepChannelOpen, true);
  });
  assert.equal(response.ok, true);
  assert.deepEqual(JSON.parse(JSON.stringify(response.whitelist)), whitelist);
  assert.deepEqual(JSON.parse(JSON.stringify(response.rules)), rules);
  assert.deepEqual(state.__whitelist, whitelist);
});
