"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { normalizeIp, classifyIp, isLoopbackIp, getRequestIp } = require("../ip-attribution");

test("normalizes IPv4-mapped IPv6 without inventing an endpoint address", () => {
  assert.equal(normalizeIp("::ffff:192.168.1.8"), "192.168.1.8");
  assert.equal(classifyIp("::ffff:192.168.1.8", "connection").ipType, "private-v4");
});

test("classifies valid IPv4 and IPv6, including loopback and private ranges", () => {
  assert.equal(classifyIp("127.0.0.1").ipType, "loopback-v4");
  assert.equal(classifyIp("::1").ipType, "loopback-v6");
  assert.equal(classifyIp("10.2.3.4").ipType, "private-v4");
  assert.equal(classifyIp("2001:db8::2").ipType, "public-v6");
  assert.equal(isLoopbackIp("::ffff:127.0.0.1"), true);
  assert.equal(isLoopbackIp("192.168.1.5"), false);
});

test("invalid or missing IPs remain unavailable instead of becoming a server IP", () => {
  assert.deepEqual(classifyIp("not-an-ip"), {
    ip: null, ipSource: "unknown", ipType: "unknown", ipConfidence: "unavailable",
  });
});

test("request attribution uses forwarded IP only when Express marks a trusted proxy hop", () => {
  const req = { ip: "203.0.113.7", ips: [], socket: { remoteAddress: "::1" } };
  assert.deepEqual(getRequestIp(req), classifyIp("::1", "connection"));
  req.ips = ["203.0.113.7"];
  assert.deepEqual(getRequestIp(req), classifyIp("203.0.113.7", "trusted-proxy"));
});
