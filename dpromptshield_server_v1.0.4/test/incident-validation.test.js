"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { validateIncidentPayload } = require("../incident-validation");

const valid = () => ({
  ts: "2026-10-18T10:00:00.000Z",
  site: "chatgpt.com",
  action: "BLOCKED",
  promptLength: 120,
  findings: [{ type: "EMAIL", masked: "u***@example.com", action: "block" }],
});

test("accepts and normalizes a valid incident without retaining unknown fields", () => {
  const result = validateIncidentPayload({ ...valid(), rawPrompt: "must not be persisted" });
  assert.equal(result.ok, true);
  assert.equal(result.value.ts, "2026-10-18T10:00:00.000Z");
  assert.equal(Object.hasOwn(result.value, "rawPrompt"), false);
});

test("rejects invalid timestamps, oversized findings, and malformed finding data", () => {
  assert.equal(validateIncidentPayload({ ...valid(), ts: "not-a-date" }).ok, false);
  assert.equal(validateIncidentPayload({ ...valid(), findings: Array(101).fill({ type: "EMAIL" }) }).ok, false);
  assert.equal(validateIncidentPayload({ ...valid(), findings: [{ type: "EMAIL", masked: "x".repeat(201) }] }).ok, false);
});

test("rejects full URLs where a hostname is expected and unknown actions", () => {
  assert.equal(validateIncidentPayload({ ...valid(), site: "https://chatgpt.com/path" }).ok, false);
  assert.equal(validateIncidentPayload({ ...valid(), action: "ALLOW_EVERYTHING" }).ok, false);
});

test("bounds optional fields and defaults missing masked examples to redacted", () => {
  const result = validateIncidentPayload({ ...valid(), findings: [{ type: "NIK" }], employeeId: "x".repeat(150) });
  assert.equal(result.ok, true);
  assert.equal(result.value.findings[0].masked, "[REDACTED]");
  assert.equal(result.value.employeeId.length, 100);
});
