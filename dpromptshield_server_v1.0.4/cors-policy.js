"use strict";

const DEFAULT_ALLOWED_ORIGINS = [
  // Stable ID derived from the public key in the shipped Chrome extension manifest.
  "chrome-extension://dekohbbgboflmeikbohfokimiojiioci",
];

function parseAllowedOrigins(value) {
  const configured = typeof value === "string"
    ? value.split(",").map((origin) => origin.trim()).filter(Boolean)
    : [];
  return new Set(configured.length ? configured : DEFAULT_ALLOWED_ORIGINS);
}

function isOriginAllowed(origin, allowedOrigins) {
  // Non-browser clients and same-origin requests may omit Origin.
  if (!origin) return true;
  if (!(allowedOrigins instanceof Set)) return false;
  return allowedOrigins.has(origin);
}

module.exports = { DEFAULT_ALLOWED_ORIGINS, parseAllowedOrigins, isOriginAllowed };
