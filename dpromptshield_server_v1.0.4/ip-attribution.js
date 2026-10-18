"use strict";

const net = require("node:net");

function normalizeIp(raw) {
  if (typeof raw !== "string") return null;
  let ip = raw.trim();
  if (!ip || ip.length > 64) return null;
  if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.slice(1, -1);
  if (ip.toLowerCase().startsWith("::ffff:")) {
    const mapped = ip.slice(7);
    if (net.isIPv4(mapped)) ip = mapped;
  }
  return net.isIP(ip) ? ip.toLowerCase() : null;
}

function classifyIp(raw, source = "unknown") {
  const ip = normalizeIp(raw);
  if (!ip) return { ip: null, ipSource: "unknown", ipType: "unknown", ipConfidence: "unavailable" };

  let ipType;
  if (ip === "::1") ipType = "loopback-v6";
  else if (ip === "127.0.0.1" || ip.startsWith("127.")) ipType = "loopback-v4";
  else if (net.isIPv4(ip)) {
    const octets = ip.split(".").map(Number);
    if (octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
        (octets[0] === 192 && octets[1] === 168)) ipType = "private-v4";
    else if (octets[0] === 169 && octets[1] === 254) ipType = "link-local-v4";
    else ipType = "public-v4";
  } else if (ip.startsWith("fe80:")) ipType = "link-local-v6";
  else if (/^(fc|fd)/.test(ip)) ipType = "private-v6";
  else ipType = "public-v6";

  // "observed" means the address was present on the TCP path; it does not
  // assert that the address identifies an endpoint behind a NAT/proxy.
  return { ip, ipSource: source, ipType, ipConfidence: "observed" };
}

function isLoopbackIp(raw) {
  const ip = normalizeIp(raw);
  return ip === "::1" || (ip !== null && net.isIPv4(ip) && ip.startsWith("127."));
}

function getRequestIp(req) {
  const trustedForwarding = Array.isArray(req.ips) && req.ips.length > 0;
  const raw = trustedForwarding ? req.ip : req.socket?.remoteAddress;
  return classifyIp(raw, trustedForwarding ? "trusted-proxy" : "connection");
}

module.exports = { normalizeIp, classifyIp, isLoopbackIp, getRequestIp };
