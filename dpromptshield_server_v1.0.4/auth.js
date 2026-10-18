"use strict";
// ---------------------------------------------------------------------------
// DPromptShield console authentication
//
//  * Two roles: "superadmin" (one, seeded) and "admin".
//  * Only the superadmin can add / delete admins (see /api/admins below).
//  * Every account — superadmin included — can change its OWN password only.
//  * Passwords are stored as salted scrypt hashes (Node built-in crypto, no
//    extra dependency). Plaintext is never stored or logged.
//  * Sessions are random 256-bit tokens kept in server memory and sent in an
//    HttpOnly + SameSite=Strict cookie. Restarting the server signs everyone
//    out. Deleting an admin or changing a password revokes sessions at once.
//  * Idle timeout: a session also ends after SESSION_IDLE_MINUTES (default 15)
//    without real admin activity. Only an explicit heartbeat from the console
//    (POST /api/auth/activity, sent when someone actually uses it) or another
//    state-changing request refreshes it. Background GET polling and /auth/me
//    do NOT, so an unattended console cannot stay signed in by auto-refreshing.
//  * The extension's four endpoints stay open (see PUBLIC_ROUTES) — they are
//    called by every employee's browser and carry no admin credentials.
//    Everything else under /api requires a logged-in session.
// ---------------------------------------------------------------------------

const crypto = require("crypto");
const express = require("express");
const { promisify } = require("util");
const scrypt = promisify(crypto.scrypt);

// First-run seed accounts. Used ONLY when dbo.DPromptShieldAdmin is empty;
// after that the database is the source of truth, so changing a password in
// the console makes the values below irrelevant.
const DEFAULT_ACCOUNTS = [
  { username: process.env.INITIAL_SUPERADMIN_USERNAME || "superadmin", password: process.env.INITIAL_SUPERADMIN_PASSWORD, role: "superadmin" },
  { username: process.env.INITIAL_ADMIN_USERNAME || "admin", password: process.env.INITIAL_ADMIN_PASSWORD, role: "admin" },
];

const SESSION_COOKIE = "dps_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;          // 8 hours, absolute
// Idle timeout (minutes of no activity before the next login is required).
// Override with SESSION_IDLE_MINUTES; anything that is not a positive number
// falls back to 15, so a typo can never silently disable the timeout.
const SESSION_IDLE_MS = (() => {
  const m = Number(process.env.SESSION_IDLE_MINUTES);
  return (Number.isFinite(m) && m > 0 ? m : 15) * 60 * 1000;
})();
const COOKIE_SECURE  = process.env.COOKIE_SECURE === "true"; // set true once served over HTTPS
const USERNAME_RE    = /^[A-Za-z0-9._-]{3,50}$/;

// Endpoints that must work without a console login (extension traffic).
// Keys are "METHOD /path" relative to /api, lower-cased.
const PUBLIC_ROUTES = new Set([
  "POST /pii-logs",       // extension reports an incident
  "GET /policy-stream",   // extension's live policy push (SSE)
  "GET /health",
  "POST /auth/login",
]);

// ---------------------------------------------------------------------------
// Password hashing
// ---------------------------------------------------------------------------
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const N = 16384, r = 8, p = 1;
  const key = await scrypt(pw, salt, 64, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString("base64")}$${key.toString("base64")}`;
}

async function verifyPassword(pw, stored) {
  try {
    const [alg, N, r, p, saltB64, keyB64] = String(stored).split("$");
    if (alg !== "scrypt") return false;
    const salt = Buffer.from(saltB64, "base64");
    const expected = Buffer.from(keyB64, "base64");
    const key = await scrypt(pw, salt, expected.length, { N: +N, r: +r, p: +p });
    return crypto.timingSafeEqual(key, expected);
  } catch (_) {
    return false;
  }
}

function checkPasswordPolicy(pw, username) {
  if (typeof pw !== "string" || !pw) return "Password is required.";
  if (pw.length < 8) return "Password must be at least 8 characters.";
  if (pw.length > 128) return "Password must be 128 characters or fewer.";
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return "Password must contain at least one letter and one number.";
  if (username && pw.toLowerCase() === String(username).toLowerCase()) return "Password must not be the same as the username.";
  return null;
}

// ---------------------------------------------------------------------------
// Failed-attempt limiter (in memory)
// ---------------------------------------------------------------------------
function makeLimiter({ max, windowMs, lockMs }) {
  const m = new Map();
  return {
    // Returns ms remaining on a lock, or 0 if the key may proceed.
    check(key) {
      const e = m.get(key);
      if (!e) return 0;
      const now = Date.now();
      if (e.lockedUntil > now) return e.lockedUntil - now;
      if (e.lockedUntil || now - e.first > windowMs) m.delete(key);
      return 0;
    },
    fail(key) {
      const now = Date.now();
      let e = m.get(key);
      if (!e || now - e.first > windowMs) { e = { count: 0, first: now, lockedUntil: 0 }; m.set(key, e); }
      e.count++;
      if (e.count >= max) e.lockedUntil = now + lockMs;
    },
    reset(key) { m.delete(key); },
    sweep() {
      const now = Date.now();
      for (const [k, e] of m) if (e.lockedUntil <= now && now - e.first > windowMs) m.delete(k);
    },
  };
}

// ---------------------------------------------------------------------------
// SQL repository (swappable so the logic can be tested without a database)
// ---------------------------------------------------------------------------
function makeSqlRepo({ sql, getPool }) {
  return {
    async ensureSchema() {
      const p = await getPool();
      await p.request().query(`
        IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldAdmin')
        CREATE TABLE dbo.DPromptShieldAdmin (
            Id                INT IDENTITY(1,1) PRIMARY KEY,
            Username          NVARCHAR(50)  NOT NULL UNIQUE,
            PasswordHash      NVARCHAR(300) NOT NULL,           -- scrypt$N$r$p$salt$hash
            Role              NVARCHAR(20)  NOT NULL CONSTRAINT DF_DPromptShieldAdmin_Role DEFAULT 'admin',
            CreatedAt         DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
            CreatedBy         NVARCHAR(50)  NULL,
            PasswordChangedAt DATETIME2     NULL,
            LastLoginAt       DATETIME2     NULL,
            CONSTRAINT CK_DPromptShieldAdmin_Role CHECK (Role IN ('superadmin', 'admin'))
        );
      `);
    },
    async count() {
      const p = await getPool();
      const r = await p.request().query(`SELECT COUNT(*) AS c FROM dbo.DPromptShieldAdmin`);
      return r.recordset[0].c;
    },
    async findByUsername(username) {
      const p = await getPool();
      const r = p.request();
      r.input("u", sql.NVarChar(50), username);
      const res = await r.query(`
        SELECT Id, Username, PasswordHash, Role FROM dbo.DPromptShieldAdmin
        WHERE LOWER(Username) = LOWER(@u)`);
      return res.recordset[0] || null;
    },
    async findById(id) {
      const p = await getPool();
      const r = p.request();
      r.input("id", sql.Int, id);
      const res = await r.query(`
        SELECT Id, Username, PasswordHash, Role FROM dbo.DPromptShieldAdmin WHERE Id = @id`);
      return res.recordset[0] || null;
    },
    async list() {
      const p = await getPool();
      const res = await p.request().query(`
        SELECT Id, Username, Role, CreatedAt, CreatedBy, LastLoginAt
        FROM dbo.DPromptShieldAdmin
        ORDER BY CASE WHEN Role = 'superadmin' THEN 0 ELSE 1 END, Username`);
      return res.recordset;
    },
    async insert({ username, hash, role, createdBy }) {
      const p = await getPool();
      const r = p.request();
      r.input("u", sql.NVarChar(50), username);
      r.input("h", sql.NVarChar(300), hash);
      r.input("role", sql.NVarChar(20), role);
      r.input("by", sql.NVarChar(50), createdBy || null);
      const res = await r.query(`
        INSERT INTO dbo.DPromptShieldAdmin (Username, PasswordHash, Role, CreatedBy)
        OUTPUT INSERTED.Id
        VALUES (@u, @h, @role, @by)`);
      return res.recordset[0].Id;
    },
    async remove(id) {
      const p = await getPool();
      const r = p.request();
      r.input("id", sql.Int, id);
      await r.query(`DELETE FROM dbo.DPromptShieldAdmin WHERE Id = @id`);
    },
    async setPassword(id, hash) {
      const p = await getPool();
      const r = p.request();
      r.input("id", sql.Int, id);
      r.input("h", sql.NVarChar(300), hash);
      await r.query(`
        UPDATE dbo.DPromptShieldAdmin
        SET PasswordHash = @h, PasswordChangedAt = SYSUTCDATETIME()
        WHERE Id = @id`);
    },
    async touchLogin(id) {
      const p = await getPool();
      const r = p.request();
      r.input("id", sql.Int, id);
      await r.query(`UPDATE dbo.DPromptShieldAdmin SET LastLoginAt = SYSUTCDATETIME() WHERE Id = @id`);
    },
  };
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------
function createAuth({ sql, getPool, repo }) {
  repo = repo || makeSqlRepo({ sql, getPool });

  // ---- sessions -----------------------------------------------------------
  const sessions = new Map(); // token -> { userId, username, role, expires, lastActivity }
  // Tokens that timed out from inactivity, kept briefly so the browser can be
  // told "you were signed out for inactivity" instead of a bare login page.
  const idleExpired = new Map(); // token -> time it timed out

  function parseCookies(req) {
    const out = {};
    const h = req.headers.cookie;
    if (!h) return out;
    for (const part of h.split(";")) {
      const i = part.indexOf("=");
      if (i < 0) continue;
      const k = part.slice(0, i).trim();
      const v = part.slice(i + 1).trim();
      try { out[k] = decodeURIComponent(v); } catch (_) { out[k] = v; }
    }
    return out;
  }

  function getSession(req) {
    const token = parseCookies(req)[SESSION_COOKIE];
    if (!token) return null;
    const s = sessions.get(token);
    if (!s) return null;
    const now = Date.now();
    if (s.expires <= now) { sessions.delete(token); return null; }
    if (now - s.lastActivity > SESSION_IDLE_MS) { expireForIdle(token); return null; }
    return { token, ...s };
  }

  function expireForIdle(token) {
    sessions.delete(token);
    idleExpired.set(token, Date.now());
  }
  function wasIdleExpired(req) {
    const token = parseCookies(req)[SESSION_COOKIE];
    return !!token && idleExpired.has(token);
  }
  function touchSession(token) {
    const s = sessions.get(token);
    if (s) s.lastActivity = Date.now();
  }

  function createSession(user) {
    const token = crypto.randomBytes(32).toString("base64url");
    sessions.set(token, {
      userId: user.Id, username: user.Username, role: user.Role,
      expires: Date.now() + SESSION_TTL_MS,
      lastActivity: Date.now(),
    });
    return token;
  }

  function destroyUserSessions(userId, exceptToken) {
    for (const [t, s] of sessions) {
      if (s.userId === userId && t !== exceptToken) sessions.delete(t);
    }
  }

  function setSessionCookie(res, token) {
    res.setHeader("Set-Cookie",
      `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}${COOKIE_SECURE ? "; Secure" : ""}`);
  }
  function clearSessionCookie(res) {
    res.setHeader("Set-Cookie",
      `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${COOKIE_SECURE ? "; Secure" : ""}`);
  }

  // ---- limiters -----------------------------------------------------------
  const loginByUserIp = makeLimiter({ max: 5,  windowMs: 15 * 60_000, lockMs: 15 * 60_000 });
  const loginByIp     = makeLimiter({ max: 20, windowMs: 15 * 60_000, lockMs: 15 * 60_000 });
  const changePwLimit = makeLimiter({ max: 5,  windowMs: 15 * 60_000, lockMs: 15 * 60_000 });

  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [t, s] of sessions) {
      if (s.expires <= now) sessions.delete(t);
      else if (now - s.lastActivity > SESSION_IDLE_MS) expireForIdle(t);
    }
    for (const [t, at] of idleExpired) if (now - at > 60 * 60_000) idleExpired.delete(t);
    loginByUserIp.sweep(); loginByIp.sweep(); changePwLimit.sweep();
  }, 10 * 60_000);
  sweeper.unref();

  // A hash to verify against when the username doesn't exist, so response
  // time doesn't reveal which usernames are real.
  let dummyHash = null;
  const getDummyHash = async () => (dummyHash ||= await hashPassword("not-a-real-password-1"));

  function clientIp(req) {
    let ip = req.ip || req.socket.remoteAddress || "";
    if (ip.startsWith("::ffff:")) ip = ip.slice(7);
    return ip;
  }

  // ---- seeding ------------------------------------------------------------
  async function ensureAuthSchema() {
    await repo.ensureSchema();
    if ((await repo.count()) === 0) {
      if (DEFAULT_ACCOUNTS.some(a => typeof a.password !== "string" || a.password.length < 12)) {
        throw new Error("Admin table is empty. Set INITIAL_SUPERADMIN_PASSWORD and INITIAL_ADMIN_PASSWORD (12+ characters) through Secret Manager before first startup.");
      }
      for (const a of DEFAULT_ACCOUNTS) {
        await repo.insert({ username: a.username, hash: await hashPassword(a.password), role: a.role, createdBy: "system" });
      }
      console.log("auth: first-run admin accounts provisioned from environment secrets");
    }
  }

  // ---- middleware ---------------------------------------------------------
  function isPublic(req) {
    const path = req.path.toLowerCase().replace(/\/+$/, "");
    const method = req.method === "HEAD" ? "GET" : req.method;
    if (PUBLIC_ROUTES.has(`${method} ${path}`)) return true;
    // Extension sync polls only. The dashboard's own (full-list) calls omit
    // enabledOnly and therefore require a login.
    if (method === "GET" && req.query.enabledOnly === "true" &&
        (path === "/monitored-urls" || path === "/pii-rules")) return true;
    return false;
  }

  // Mounted on /api: everything not in the public list needs a session.
  function apiGuard(req, res, next) {
    if (isPublic(req)) return next();
    const s = getSession(req);
    if (!s) {
      return res.status(401).json(wasIdleExpired(req)
        ? { error: "signed out due to inactivity", reason: "idle" }
        : { error: "authentication required" });
    }
    // Only a real admin action refreshes the idle timer: a state-changing
    // request (this includes the console's POST /auth/activity heartbeat).
    // Plain GETs are what the dashboard's auto-refresh sends every few
    // seconds, so counting them would mean it never times out.
    if (req.method !== "GET" && req.method !== "HEAD" && req.method !== "OPTIONS") touchSession(s.token);
    req.user = { id: s.userId, username: s.username, role: s.role, token: s.token };
    next();
  }

  function requireSuperadmin(req, res, next) {
    if (req.user?.role !== "superadmin") return res.status(403).json({ error: "superadmin only" });
    next();
  }

  // Mounted on the whole app, ahead of express.static: keeps the console page
  // itself behind login (the data is protected by apiGuard regardless).
  function pageGate(req, res, next) {
    let p;
    try { p = decodeURIComponent(req.path).toLowerCase(); } catch (_) { return res.status(400).end(); }
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    if (p === "/dashboard.html" || p === "/dashboard" || p === "/ai-lab.html" || p === "/domain-policy.html") {
      if (!getSession(req)) return res.redirect(wasIdleExpired(req) ? "/login.html?expired=1" : "/login.html");
      res.setHeader("Cache-Control", "no-store");
    }
    next();
  }

  const wrap = (fn) => (req, res) =>
    Promise.resolve(fn(req, res)).catch((err) => {
      console.error(`${req.method} ${req.originalUrl} failed:`, err.message);
      if (!res.headersSent) res.status(500).json({ error: "internal error" });
    });

  // ---- /api/auth ----------------------------------------------------------
  const authRouter = express.Router();

  authRouter.post("/login", wrap(async (req, res) => {
    const { username, password } = req.body || {};
    const ip = clientIp(req);
    const badInput = typeof username !== "string" || typeof password !== "string" ||
      !username || !password || username.length > 50 || password.length > 128;

    const keyUserIp = `${ip}|${String(username || "").toLowerCase()}`;
    const wait = Math.max(loginByIp.check(ip), badInput ? 0 : loginByUserIp.check(keyUserIp));
    if (wait > 0) {
      res.setHeader("Retry-After", Math.ceil(wait / 1000));
      return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(wait / 60000)} minute(s).` });
    }

    const fail = async () => {
      loginByIp.fail(ip);
      if (!badInput) loginByUserIp.fail(keyUserIp);
      return res.status(401).json({ error: "Invalid username or password." });
    };
    if (badInput) return fail();

    const user = await repo.findByUsername(username);
    const ok = await verifyPassword(password, user ? user.PasswordHash : await getDummyHash());
    if (!user || !ok) return fail();

    loginByUserIp.reset(keyUserIp);
    const token = createSession(user);
    setSessionCookie(res, token);
    repo.touchLogin(user.Id).catch((e) => console.warn("touchLogin failed:", e.message));
    res.json({ ok: true, username: user.Username, role: user.Role });
  }));

  authRouter.post("/logout", (req, res) => {
    if (req.user) sessions.delete(req.user.token);
    clearSessionCookie(res);
    res.json({ ok: true });
  });

  // Deliberately does not refresh the idle timer (the login page calls this
  // just to check for a session). idleTimeoutMs lets the console mirror the
  // server's setting for its warning popup.
  authRouter.get("/me", (req, res) => {
    res.json({ username: req.user.username, role: req.user.role, idleTimeoutMs: SESSION_IDLE_MS });
  });

  // Heartbeat: the console sends this only while someone is actually using
  // it. The timer refresh itself happens in apiGuard (it is a POST).
  authRouter.post("/activity", (_req, res) => res.json({ ok: true }));

  // Any logged-in account may change ITS OWN password — nobody else's.
  authRouter.post("/change-password", wrap(async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    if (typeof currentPassword !== "string" || !currentPassword) {
      return res.status(400).json({ error: "Current password is required." });
    }
    const policyErr = checkPasswordPolicy(newPassword, req.user.username);
    if (policyErr) return res.status(400).json({ error: policyErr });
    if (newPassword === currentPassword) {
      return res.status(400).json({ error: "New password must be different from the current password." });
    }

    const key = `chpw|${req.user.id}`;
    const wait = changePwLimit.check(key);
    if (wait > 0) {
      res.setHeader("Retry-After", Math.ceil(wait / 1000));
      return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(wait / 60000)} minute(s).` });
    }

    const user = await repo.findById(req.user.id);
    if (!user) return res.status(401).json({ error: "authentication required" });
    if (!(await verifyPassword(currentPassword, user.PasswordHash))) {
      changePwLimit.fail(key);
      // 400, not 401: a wrong current password must not look like "session expired".
      return res.status(400).json({ error: "Current password is incorrect." });
    }

    changePwLimit.reset(key);
    await repo.setPassword(user.Id, await hashPassword(newPassword));
    destroyUserSessions(user.Id, req.user.token); // sign out any other devices
    res.json({ ok: true });
  }));

  // ---- /api/admins (superadmin only) -------------------------------------
  const adminRouter = express.Router();
  adminRouter.use(requireSuperadmin);

  adminRouter.get("/", wrap(async (_req, res) => {
    res.json({ admins: await repo.list() });
  }));

  adminRouter.post("/", wrap(async (req, res) => {
    const { username, password } = req.body || {};
    const name = typeof username === "string" ? username.trim() : "";
    if (!USERNAME_RE.test(name)) {
      return res.status(400).json({ error: "Username must be 3–50 characters: letters, numbers, dot, dash or underscore." });
    }
    const policyErr = checkPasswordPolicy(password, name);
    if (policyErr) return res.status(400).json({ error: policyErr });
    if (await repo.findByUsername(name)) {
      return res.status(409).json({ error: "That username already exists." });
    }
    try {
      // Role is always 'admin' here — a second superadmin cannot be created from the API.
      const id = await repo.insert({
        username: name, hash: await hashPassword(password), role: "admin", createdBy: req.user.username,
      });
      res.status(201).json({ ok: true, id, username: name });
    } catch (err) {
      if (/unique|duplicate/i.test(err.message)) {
        return res.status(409).json({ error: "That username already exists." });
      }
      throw err;
    }
  }));

  adminRouter.delete("/:id", wrap(async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: "invalid id" });
    const target = await repo.findById(id);
    if (!target) return res.status(404).json({ error: "Admin not found." });
    if (target.Role === "superadmin" || target.Id === req.user.id) {
      return res.status(403).json({ error: "The superadmin account cannot be deleted." });
    }
    await repo.remove(id);
    destroyUserSessions(id); // kick them out immediately
    res.json({ ok: true });
  }));

  return { ensureAuthSchema, pageGate, apiGuard, authRouter, adminRouter, hashPassword, _sessions: sessions };
}

module.exports = createAuth;
module.exports.hashPassword = hashPassword;
module.exports.SESSION_IDLE_MS = SESSION_IDLE_MS;
module.exports.checkPasswordPolicy = checkPasswordPolicy;
