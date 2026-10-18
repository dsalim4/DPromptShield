"use strict";

const ACTIONS = new Set(["allow", "monitor", "warn", "require_approval", "block"]);
const RISKS = new Set(["critical", "high", "medium", "low", "unknown"]);
const SENSITIVITY_RANK = { public: 0, internal: 1, confidential: 2, restricted: 3, personal_data: 2, sensitive_personal_data: 3, credential_secret: 3, financial_data: 3, intellectual_property: 2, unknown: 2 };

function normalizeDomain(input) {
  if (typeof input !== "string" || !input.trim() || input.length > 2048) return null;
  let raw = input.trim().toLowerCase();
  try {
    if (!raw.includes("://")) raw = `https://${raw}`;
    const u = new URL(raw);
    if (!["http:", "https:"].includes(u.protocol) || u.username || u.password) return null;
    const host = u.hostname.toLowerCase().replace(/\.$/, "");
    if (!host || host.length > 253 || host === "localhost" || !host.includes(".")) return null;
    if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) return null;
    return host;
  } catch { return null; }
}

function evaluatePolicy(input = {}) {
  const domain = normalizeDomain(input.domain);
  if (!domain) return { decision: "block", reason: "invalid_destination", domain: null, policyId: null, policyVersion: null, evidence: ["Destination must be a valid DNS hostname."], requiresApproval: false };
  const category = String(input.dataCategory || "unknown").toLowerCase().replace(/[ -]+/g, "_");
  const rank = SENSITIVITY_RANK[category] ?? SENSITIVITY_RANK.unknown;
  const policy = input.policy && normalizeDomain(input.policy.Domain || input.policy.domain) === domain ? input.policy : null;
  const approved = Boolean(policy && (policy.IsApproved === true || policy.IsApproved === 1 || policy.isApproved === true));
  const risk = policy && RISKS.has(String(policy.RiskLevel || policy.riskLevel).toLowerCase()) ? String(policy.RiskLevel || policy.riskLevel).toLowerCase() : "unknown";
  const configuredAction = policy && ACTIONS.has(String(policy.Action || policy.action).toLowerCase()) ? String(policy.Action || policy.action).toLowerCase() : "monitor";
  const evidence = [`destination=${domain}`, `data_category=${category}`, `domain_policy=${policy ? "matched" : "unknown"}`, `policy_approved=${approved}`, `domain_risk=${risk}`];
  let decision = "monitor", reason = "unknown_destination_monitor";
  let requiresApproval = false;

  if (rank >= 3) {
    decision = "block"; reason = "restricted_or_high_sensitivity_data";
  } else if (policy && risk === "critical") {
    decision = "block"; reason = "critical_domain_risk";
  } else if (policy && risk === "high" && ["allow", "monitor"].includes(configuredAction)) {
    decision = "require_approval"; reason = "high_risk_destination_requires_approval"; requiresApproval = true;
  } else if (!policy || !approved) {
    decision = input.unknownDomainAction === "block" ? "block" : "monitor";
    reason = policy ? "domain_policy_not_approved" : "unknown_destination_monitor";
  } else {
    decision = configuredAction;
    reason = `approved_domain_policy_${configuredAction}`;
    requiresApproval = decision === "require_approval";
  }
  evidence.push(`decision=${decision}`, `reason=${reason}`);
  return { decision, reason, domain, policyId: policy?.Id ?? policy?.id ?? null, policyVersion: policy?.Version ?? policy?.version ?? null, dataCategory: category, destinationRisk: risk, requiresApproval, evidence };
}

function validateDomainPolicy(body = {}) {
  const domain = normalizeDomain(body.domain);
  if (!domain) return { ok: false, error: "A valid DNS hostname or http(s) URL is required." };
  const category = String(body.category || "unknown").trim().toLowerCase();
  const riskLevel = String(body.riskLevel || "unknown").trim().toLowerCase();
  const action = String(body.action || "monitor").trim().toLowerCase();
  if (category.length > 50 || !/^[a-z0-9_-]+$/.test(category)) return { ok: false, error: "Invalid category." };
  if (!RISKS.has(riskLevel)) return { ok: false, error: "Invalid riskLevel." };
  if (!ACTIONS.has(action)) return { ok: false, error: "Invalid action." };
  const notes = typeof body.notes === "string" ? body.notes.trim().slice(0, 2000) : "";
  const source = typeof body.source === "string" && ["manual", "threat_intelligence", "import"].includes(body.source) ? body.source : "manual";
  return { ok: true, value: { domain, category, riskLevel, action, notes, source } };
}

module.exports = { normalizeDomain, evaluatePolicy, validateDomainPolicy, ACTIONS, RISKS };
