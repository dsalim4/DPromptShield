"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { DEFAULT_ALLOWED_ORIGINS, parseAllowedOrigins, isOriginAllowed } = require("../cors-policy");

test("defaults to the shipped Chrome extension origin, not arbitrary origins", () => {
  const allowed = parseAllowedOrigins("");
  assert.deepEqual([...allowed], DEFAULT_ALLOWED_ORIGINS);
  assert.equal(isOriginAllowed(DEFAULT_ALLOWED_ORIGINS[0], allowed), true);
  assert.equal(isOriginAllowed("https://attacker.example", allowed), false);
});

test("operator allowlist is exact and supports non-browser clients without Origin", () => {
  const allowed = parseAllowedOrigins("https://console.example, chrome-extension://abc");
  assert.equal(isOriginAllowed("https://console.example", allowed), true);
  assert.equal(isOriginAllowed("https://console.example.attacker.example", allowed), false);
  assert.equal(isOriginAllowed(undefined, allowed), true);
});
