"use strict";

const ALLOWED_ACTIONS = new Set(["BLOCKED", "PASTE_BLOCKED", "DROP_BLOCKED", "MONITORED"]);
const MAX_FINDINGS = 100;

function validateIncidentPayload(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, error: "payload must be an object" };
  }
  if (typeof value.ts !== "string" || value.ts.length > 64 || !Number.isFinite(Date.parse(value.ts))) {
    return { ok: false, error: "ts must be a valid date-time string" };
  }
  if (!Array.isArray(value.findings) || value.findings.length === 0 || value.findings.length > MAX_FINDINGS) {
    return { ok: false, error: `findings must contain 1-${MAX_FINDINGS} items` };
  }
  const findings = [];
  for (const finding of value.findings) {
    if (!finding || typeof finding !== "object" || Array.isArray(finding)) {
      return { ok: false, error: "each finding must be an object" };
    }
    if (typeof finding.type !== "string" || !/^[A-Za-z0-9_. -]{1,50}$/.test(finding.type)) {
      return { ok: false, error: "finding type is invalid" };
    }
    if (finding.masked !== undefined && (typeof finding.masked !== "string" || finding.masked.length > 200)) {
      return { ok: false, error: "finding masked example is invalid" };
    }
    if (finding.action !== undefined && !["block", "monitor", "mask"].includes(finding.action)) {
      return { ok: false, error: "finding action is invalid" };
    }
    findings.push({
      type: finding.type,
      masked: typeof finding.masked === "string" ? finding.masked : "[REDACTED]",
      action: finding.action || "block",
    });
  }
  if (value.action !== undefined && !ALLOWED_ACTIONS.has(value.action)) {
    return { ok: false, error: "action is invalid" };
  }
  const promptLength = value.promptLength === undefined ? null : value.promptLength;
  if (promptLength !== null && (!Number.isInteger(promptLength) || promptLength < 0 || promptLength > 10_000_000)) {
    return { ok: false, error: "promptLength is invalid" };
  }
  const site = value.site === undefined ? null : value.site;
  if (site !== null && (typeof site !== "string" || site.length > 255 || /[\s/\\?#]/.test(site))) {
    return { ok: false, error: "site must be a hostname, not a URL" };
  }
  return {
    ok: true,
    value: {
      ts: new Date(value.ts).toISOString(),
      site,
      action: value.action || "BLOCKED",
      promptLength,
      findings,
      // These extension-provided fields are claims, not verified identity.
      employeeId: typeof value.employeeId === "string" ? value.employeeId.slice(0, 100) : null,
      deviceLabel: typeof value.deviceLabel === "string" ? value.deviceLabel.slice(0, 255) : null,
      deviceId: typeof value.deviceId === "string" ? value.deviceId.slice(0, 100) : null,
      browserInfo: typeof value.browserInfo === "string" ? value.browserInfo.slice(0, 500) : null,
    },
  };
}

module.exports = { validateIncidentPayload, MAX_FINDINGS };
