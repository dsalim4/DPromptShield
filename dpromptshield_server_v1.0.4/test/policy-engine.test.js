"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { normalizeDomain, evaluatePolicy, validateDomainPolicy } = require("../policy-engine");

test("normalizes URLs to hostnames without paths or credentials", () => {
  assert.equal(normalizeDomain("HTTPS://Example.COM/path?q=1"), "example.com");
  assert.equal(normalizeDomain("example.com."), "example.com");
  assert.equal(normalizeDomain("https://user:pass@example.com"), null);
  assert.equal(normalizeDomain("javascript:alert(1)"), null);
  assert.equal(normalizeDomain("localhost"), null);
});

test("unknown and unapproved destinations never become allow", () => {
  assert.equal(evaluatePolicy({ domain: "new.example", dataCategory: "internal" }).decision, "monitor");
  assert.equal(evaluatePolicy({ domain: "new.example", dataCategory: "internal", unknownDomainAction: "block" }).decision, "block");
  assert.equal(evaluatePolicy({ domain: "new.example", dataCategory: "internal", policy: { Domain: "new.example", Action: "allow", IsApproved: false } }).decision, "monitor");
});

test("restricted data and critical/high-risk destinations override allow", () => {
  const allow = { Domain: "ai.example", Action: "allow", IsApproved: true, RiskLevel: "low", Id: 7, Version: 2 };
  assert.equal(evaluatePolicy({ domain: "ai.example", dataCategory: "restricted", policy: allow }).decision, "block");
  assert.equal(evaluatePolicy({ domain: "ai.example", dataCategory: "internal", policy: { ...allow, RiskLevel: "critical" } }).decision, "block");
  assert.equal(evaluatePolicy({ domain: "ai.example", dataCategory: "internal", policy: { ...allow, RiskLevel: "high" } }).decision, "require_approval");
});

test("approved policy returns explainable decision and policy reference", () => {
  const result = evaluatePolicy({ domain: "ai.example", dataCategory: "internal", policy: { Domain: "ai.example", Action: "warn", IsApproved: true, RiskLevel: "low", Id: 12, Version: 3 } });
  assert.equal(result.decision, "warn");
  assert.equal(result.policyId, 12);
  assert.equal(result.policyVersion, 3);
  assert.ok(result.evidence.some((x) => x === "reason=approved_domain_policy_warn"));
});

test("domain policy validation rejects invalid actions and accepts normalized valid policy", () => {
  assert.equal(validateDomainPolicy({ domain: "example.com", action: "execute" }).ok, false);
  const result = validateDomainPolicy({ domain: "https://Example.com/path", action: "block", riskLevel: "high", notes: "Review" });
  assert.equal(result.ok, true);
  assert.equal(result.value.domain, "example.com");
  assert.equal(result.value.action, "block");
});
