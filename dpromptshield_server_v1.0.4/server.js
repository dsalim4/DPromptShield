require("dotenv").config();
const path = require("path");
const express = require("express");
const cors = require("cors");
const sql = require("mssql");
const { getRequestIp, isLoopbackIp } = require("./ip-attribution");
const { parseAllowedOrigins, isOriginAllowed } = require("./cors-policy");
const { validateIncidentPayload } = require("./incident-validation");
const { normalizeDomain, evaluatePolicy, validateDomainPolicy } = require("./policy-engine");

const createAuth = require("./auth");

const app = express();
// Forwarded headers are ignored unless an operator explicitly lists trusted
// proxy hops. Express then applies its normal right-to-left proxy chain rules.
const trustedProxyIps = (process.env.TRUSTED_PROXY_IPS || "").split(",").map((x) => x.trim()).filter(Boolean);
if (trustedProxyIps.length) app.set("trust proxy", trustedProxyIps);
const allowedCorsOrigins = parseAllowedOrigins(process.env.CORS_ALLOWED_ORIGINS);
app.use(cors({
  origin(origin, callback) {
    callback(null, isOriginAllowed(origin, allowedCorsOrigins) ? origin || false : false);
  },
}));
app.use(express.json({ limit: "7mb" }));

// ---------------------------------------------------------------------------
// Console login (see auth.js)
//
// Order matters: pageGate keeps dashboard.html behind login, apiGuard then
// requires a session for every /api route EXCEPT the few the browser
// extension itself calls (incident POST, enabledOnly policy syncs, policy
// stream, health). Static files come last.
// ---------------------------------------------------------------------------
const auth = createAuth({ sql, getPool });
app.use(auth.pageGate);
app.use("/api", auth.apiGuard);
app.use("/api/auth", auth.authRouter);
app.use("/api/admins", auth.adminRouter);

app.use(express.static(path.join(__dirname, "public")));
app.get("/", (_req, res) => res.redirect("/dashboard.html"));

// ---------------------------------------------------------------------------
// Server-Sent Events — policy push
//
// Extensions connect to GET /api/policy-stream and keep the response open.
// Whenever an admin changes monitored URLs or PII rules via the dashboard,
// notifyPolicyChange() broadcasts a "policy-change" event so every connected
// extension re-syncs immediately instead of waiting for its hourly alarm.
//
// A keepalive "ping" comment is sent every 30 s so NAT/proxy timeouts don't
// silently drop idle connections.
// ---------------------------------------------------------------------------

const sseClients = new Set();

app.get("/api/policy-stream", (req, res) => {
  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.setHeader("X-Accel-Buffering", "no"); // disable nginx buffering if behind proxy
  res.flushHeaders();

  // Send an immediate ping so the client knows the stream is live.
  res.write(": ping\n\n");

  sseClients.add(res);
  console.log(`policy-stream: client connected (${sseClients.size} total)`);

  // Keepalive every 30 s — keeps NAT/proxy from closing idle connections.
  const keepalive = setInterval(() => res.write(": ping\n\n"), 30_000);

  req.on("close", () => {
    clearInterval(keepalive);
    sseClients.delete(res);
    console.log(`policy-stream: client disconnected (${sseClients.size} remaining)`);
  });
});

function notifyPolicyChange(what) {
  const payload = JSON.stringify({ what, ts: new Date().toISOString() });
  const msg = `event: policy-change\ndata: ${payload}\n\n`;
  for (const client of sseClients) {
    try { client.write(msg); } catch (_) { sseClients.delete(client); }
  }
  console.log(`policy-stream: broadcast policy-change (${what}) to ${sseClients.size} client(s)`);
}



const dbConfig = {
  server: process.env.DB_SERVER,
  port: Number(process.env.DB_PORT || 1433),
  database: process.env.DB_DATABASE,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  options: {
    encrypt: process.env.DB_ENCRYPT !== "false",
    trustServerCertificate: process.env.DB_TRUST_SERVER_CERT !== "false",
  },
};

const DEFAULT_PATTERNS = [
  "https://chatgpt.com/*",
  "https://chat.openai.com/*",
  "https://claude.ai/*",
  "https://gemini.google.com/*",
  "https://copilot.microsoft.com/*",
  "https://www.perplexity.ai/*",
  "https://grok.com/*",
  "https://chat.deepseek.com/*",
];

// Validator is a fixed whitelist the extension knows how to run locally
// (content.js), not arbitrary server-pushed code — see README for why.
// KeyMode controls how a match is compared against pasted text for the
// "typed only" check: 'digits' strips everything but numbers, 'text'
// lowercases and trims. Pattern/flags can be changed freely from the
// dashboard with no extension update; validator/keyMode choices are
// limited to what content.js actually implements.
//
// Mode is the per-rule enforcement action — the knob an admin flips day to
// day, independently for every rule:
//   'block'   — the extension stops the send/paste/drop and logs BLOCKED.
//   'monitor' — the extension lets the action through completely untouched
//               and only records it (MONITORED). The user is never
//               interrupted; the incident still lands in the console.
// New rules default to 'block', which is what every rule did before this
// column existed.
const DEFAULT_RULES = [
  { type: "NIK", label: "Indonesian NIK", pattern: "(?<!\\d)\\d(?:[ .-]?\\d){15}(?!\\d)", flags: "g", validator: "nik", keyMode: "digits", mode: "block" },
  { type: "NPWP", label: "Indonesian NPWP", pattern: "(?<!\\d)\\d{2}\\.\\d{3}\\.\\d{3}\\.\\d-\\d{3}\\.\\d{3}(?!\\d)", flags: "g", validator: "none", keyMode: "digits", mode: "block" },
  { type: "CREDIT_CARD", label: "Credit card", pattern: "(?<!\\d)\\d(?:[ -]?\\d){12,18}(?!\\d)", flags: "g", validator: "luhn", keyMode: "digits", mode: "block" },
  { type: "PHONE_ID", label: "Indonesian phone", pattern: "(?<![\\d+])(?:\\+62|62|0)[ -]?8\\d(?:[ -]?\\d){7,10}(?!\\d)", flags: "g", validator: "none", keyMode: "digits", mode: "block" },
  { type: "EMAIL", label: "Email address", pattern: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", flags: "g", validator: "none", keyMode: "text", mode: "block" },
];

let pool;
async function getPool() {
  if (!pool) pool = await sql.connect(dbConfig);
  return pool;
}

async function ensureSchema() {
  const p = await getPool();

  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldIncident')
    CREATE TABLE dbo.DPromptShieldIncident (
        Id            BIGINT IDENTITY(1,1) PRIMARY KEY,
        EventTs       DATETIME2      NOT NULL,
        SiteHost      NVARCHAR(255)  NULL,
        ActionTaken   NVARCHAR(50)   NOT NULL DEFAULT 'BLOCKED',
        PromptLength  INT            NULL,
        FindingsJson  NVARCHAR(MAX)  NOT NULL,
        ClientIp      NVARCHAR(45)   NULL,  -- IPv4 or IPv6
        EmployeeId    NVARCHAR(100)  NULL,  -- from chrome.storage.managed, if set
        DeviceLabel   NVARCHAR(255)  NULL,  -- from chrome.storage.managed, if set
        InsertedAt    DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME()
    );
  `);

  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldMonitoredUrl')
    CREATE TABLE dbo.DPromptShieldMonitoredUrl (
        Id        INT IDENTITY(1,1) PRIMARY KEY,
        Pattern   NVARCHAR(500) NOT NULL UNIQUE,
        Enabled   BIT NOT NULL DEFAULT 1,
        CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
    );
  `);

  const existingUrls = await p.request().query(`SELECT COUNT(*) AS c FROM dbo.DPromptShieldMonitoredUrl`);
  if (existingUrls.recordset[0].c === 0) {
    const r = p.request();
    for (let i = 0; i < DEFAULT_PATTERNS.length; i++) {
      r.input(`p${i}`, sql.NVarChar(500), DEFAULT_PATTERNS[i]);
    }
    const values = DEFAULT_PATTERNS.map((_, i) => `(@p${i}, 1)`).join(",");
    await r.query(`INSERT INTO dbo.DPromptShieldMonitoredUrl (Pattern, Enabled) VALUES ${values}`);
  }

  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldRule')
    CREATE TABLE dbo.DPromptShieldRule (
        Id        INT IDENTITY(1,1) PRIMARY KEY,
        Type      NVARCHAR(50)   NOT NULL UNIQUE,  -- short code, e.g. NIK, EMAIL
        Label     NVARCHAR(255)  NOT NULL,
        Pattern   NVARCHAR(1000) NOT NULL,          -- regex source, no slashes
        Flags     NVARCHAR(10)   NOT NULL DEFAULT 'g',
        Validator NVARCHAR(20)   NOT NULL DEFAULT 'none', -- 'none' | 'luhn' | 'nik'
        KeyMode   NVARCHAR(10)   NOT NULL DEFAULT 'digits', -- 'digits' | 'text'
        Mode      NVARCHAR(10)   NOT NULL CONSTRAINT DF_DPromptShieldRule_Mode DEFAULT 'block', -- 'block' | 'monitor'
        Enabled   BIT NOT NULL DEFAULT 1,
        CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
        CONSTRAINT CK_DPromptShieldRule_Mode CHECK (Mode IN ('block', 'monitor'))
    );
  `);

  // Migration for a database created before per-rule Mode existed. Every
  // rule already in the table keeps behaving exactly as it did (block).
  await p.request().query(`
    IF COL_LENGTH('dbo.DPromptShieldRule', 'Mode') IS NULL
      ALTER TABLE dbo.DPromptShieldRule
        ADD Mode NVARCHAR(10) NOT NULL CONSTRAINT DF_DPromptShieldRule_Mode DEFAULT 'block';
  `);

  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_DPromptShieldRule_Mode')
      ALTER TABLE dbo.DPromptShieldRule
        ADD CONSTRAINT CK_DPromptShieldRule_Mode CHECK (Mode IN ('block', 'monitor'));
  `);

  const existingRules = await p.request().query(`SELECT COUNT(*) AS c FROM dbo.DPromptShieldRule`);
  if (existingRules.recordset[0].c === 0) {
    for (const rule of DEFAULT_RULES) {
      const r = p.request();
      r.input("type", sql.NVarChar(50), rule.type);
      r.input("label", sql.NVarChar(255), rule.label);
      r.input("pattern", sql.NVarChar(1000), rule.pattern);
      r.input("flags", sql.NVarChar(10), rule.flags);
      r.input("validator", sql.NVarChar(20), rule.validator);
      r.input("keyMode", sql.NVarChar(10), rule.keyMode);
      r.input("mode", sql.NVarChar(10), rule.mode);
      await r.query(`
        INSERT INTO dbo.DPromptShieldRule (Type, Label, Pattern, Flags, Validator, KeyMode, Mode, Enabled)
        VALUES (@type, @label, @pattern, @flags, @validator, @keyMode, @mode, 1)
      `);
    }
  }

  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldDevice')
    CREATE TABLE dbo.DPromptShieldDevice (
        Id            INT IDENTITY(1,1) PRIMARY KEY,
        ClientIp      NVARCHAR(45) NOT NULL UNIQUE,
        FirstSeen     DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
        LastSeen      DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
        CheckinCount  INT NOT NULL DEFAULT 1
    );
  `);

  await ensureGroupSchema(p);
  await ensureSchemaV2(p);
}

// ---------------------------------------------------------------------------
// Schema V2 — backward-compatible migrations for enterprise DLP features
// ---------------------------------------------------------------------------
async function ensureSchemaV2(p) {
  // --- Incident enrichment columns ---
  const incidentCols = [
    { name: "IpSource",      type: "NVARCHAR(20)",  def: null },
    { name: "IpType",        type: "NVARCHAR(20)",  def: null },
    { name: "IpConfidence",  type: "NVARCHAR(10)",  def: null },
    { name: "ComputerName",  type: "NVARCHAR(255)", def: null },
    { name: "DeviceId",      type: "NVARCHAR(100)", def: null },
    { name: "BrowserInfo",   type: "NVARCHAR(500)", def: null },
    { name: "CorrelationId", type: "NVARCHAR(50)",  def: null },
  ];
  for (const col of incidentCols) {
    await p.request().query(`
      IF COL_LENGTH('dbo.DPromptShieldIncident', '${col.name}') IS NULL
        ALTER TABLE dbo.DPromptShieldIncident ADD ${col.name} ${col.type} NULL;
    `);
  }
  // "unavailable" is 11 characters; widen older 10-character deployments
  // non-destructively so an absent/invalid client address cannot break logs.
  await p.request().query(`
    IF COL_LENGTH('dbo.DPromptShieldIncident', 'IpConfidence') < 40
      ALTER TABLE dbo.DPromptShieldIncident ALTER COLUMN IpConfidence NVARCHAR(20) NULL;
  `);

  // --- Device enrollment ---
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldDeviceEnrollment')
    CREATE TABLE dbo.DPromptShieldDeviceEnrollment (
        Id            INT IDENTITY(1,1) PRIMARY KEY,
        DeviceId      NVARCHAR(100)  NOT NULL UNIQUE,
        ComputerName  NVARCHAR(255)  NULL,
        EmployeeId    NVARCHAR(100)  NULL,
        DeviceLabel   NVARCHAR(255)  NULL,
        EnrolledAt    DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME(),
        EnrolledBy    NVARCHAR(50)   NULL,
        LastSeen      DATETIME2      NULL,
        Status        NVARCHAR(20)   NOT NULL DEFAULT 'pending',
        CONSTRAINT CK_DeviceEnrollment_Status CHECK (Status IN ('pending','approved','rejected','revoked'))
    );
  `);

  // --- Policy documents (RAG source documents) ---
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldPolicyDocument')
    CREATE TABLE dbo.DPromptShieldPolicyDocument (
        Id              INT IDENTITY(1,1) PRIMARY KEY,
        DocumentId      NVARCHAR(50)   NOT NULL UNIQUE,
        Title           NVARCHAR(500)  NOT NULL,
        Source          NVARCHAR(255)  NULL,
        Jurisdiction    NVARCHAR(100)  NULL,
        Version         NVARCHAR(50)   NULL DEFAULT '1.0',
        EffectiveDate   DATE           NULL,
        UploadedAt      DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME(),
        UploadedBy      NVARCHAR(50)   NULL,
        Status          NVARCHAR(20)   NOT NULL DEFAULT 'processing',
        ContentHash     NVARCHAR(64)   NULL,
        FileSize        INT            NULL,
        MimeType        NVARCHAR(100)  NULL,
        ChunkCount      INT            NULL DEFAULT 0,
        ExtractedText   NVARCHAR(MAX)  NULL,
        CONSTRAINT CK_PolicyDoc_Status CHECK (Status IN ('processing','indexed','error','archived'))
    );
  `);

  // --- Policy proposals (AI-generated, awaiting approval) ---
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldPolicyProposal')
    CREATE TABLE dbo.DPromptShieldPolicyProposal (
        Id                INT IDENTITY(1,1) PRIMARY KEY,
        ProposalId        NVARCHAR(50)   NOT NULL UNIQUE,
        PolicyName        NVARCHAR(255)  NOT NULL,
        DocumentId        NVARCHAR(50)   NULL,
        RegulatorySource  NVARCHAR(255)  NULL,
        CitationRefs      NVARCHAR(MAX)  NULL,
        DataCategory      NVARCHAR(100)  NULL,
        DetectionPattern  NVARCHAR(1000) NULL,
        DetectionFlags    NVARCHAR(10)   NULL DEFAULT 'g',
        Validator         NVARCHAR(20)   NULL DEFAULT 'none',
        Scope             NVARCHAR(255)  NULL,
        TargetApps        NVARCHAR(MAX)  NULL,
        RecommendedAction NVARCHAR(20)   NULL DEFAULT 'monitor',
        Severity          NVARCHAR(20)   NULL DEFAULT 'medium',
        Confidence        FLOAT          NULL,
        Rationale         NVARCHAR(MAX)  NULL,
        FalsePositiveNotes NVARCHAR(MAX) NULL,
        TestCases         NVARCHAR(MAX)  NULL,
        ConflictingPolicies NVARCHAR(MAX) NULL,
        Status            NVARCHAR(20)   NOT NULL DEFAULT 'draft',
        Version           INT            NOT NULL DEFAULT 1,
        CreatedAt         DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME(),
        CreatedBy         NVARCHAR(50)   NULL,
        ReviewedAt        DATETIME2      NULL,
        ReviewedBy        NVARCHAR(50)   NULL,
        ReviewNotes       NVARCHAR(MAX)  NULL,
        PublishedAt       DATETIME2      NULL,
        CONSTRAINT CK_Proposal_Status CHECK (Status IN ('draft','processing','proposed','pending_approval','approved','rejected','published','disabled','archived'))
    );
  `);

  // --- Domain reputation and policy ---
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldDomainPolicy')
    CREATE TABLE dbo.DPromptShieldDomainPolicy (
        Id              INT IDENTITY(1,1) PRIMARY KEY,
        Domain          NVARCHAR(255)  NOT NULL,
        Category        NVARCHAR(50)   NULL DEFAULT 'unknown',
        RiskLevel       NVARCHAR(20)   NULL DEFAULT 'unknown',
        Action          NVARCHAR(20)   NOT NULL DEFAULT 'monitor',
        IsApproved      BIT            NOT NULL DEFAULT 0,
        Notes           NVARCHAR(MAX)  NULL,
        Source          NVARCHAR(50)   NULL DEFAULT 'manual',
        LastUpdated     DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME(),
        UpdatedBy       NVARCHAR(50)   NULL,
        CONSTRAINT CK_DomainPolicy_Action CHECK (Action IN ('allow','monitor','warn','require_approval','block')),
        CONSTRAINT CK_DomainPolicy_Risk CHECK (RiskLevel IN ('critical','high','medium','low','unknown'))
    );
  `);
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_DomainPolicy_Domain')
      CREATE UNIQUE INDEX UX_DomainPolicy_Domain ON dbo.DPromptShieldDomainPolicy(Domain);
  `);

  // --- Masking sessions (for reversible mapping) ---
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldMaskingSession')
    CREATE TABLE dbo.DPromptShieldMaskingSession (
        Id              INT IDENTITY(1,1) PRIMARY KEY,
        SessionId       NVARCHAR(50)   NOT NULL UNIQUE,
        CorrelationId   NVARCHAR(50)   NULL,
        MappingJson     NVARCHAR(MAX)  NULL,
        CreatedAt       DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME(),
        ExpiresAt       DATETIME2      NOT NULL,
        AccessCount     INT            NOT NULL DEFAULT 0
    );
  `);

  // --- Audit events (local SQL, complementing Firestore) ---
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldAuditEvent')
    CREATE TABLE dbo.DPromptShieldAuditEvent (
        Id              BIGINT IDENTITY(1,1) PRIMARY KEY,
        EventType       NVARCHAR(50)   NOT NULL,
        Actor           NVARCHAR(100)  NULL,
        CorrelationId   NVARCHAR(50)   NULL,
        Summary         NVARCHAR(1000) NULL,
        DetailsJson     NVARCHAR(MAX)  NULL,
        CreatedAt       DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME()
    );
  `);
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AuditEvent_Type')
      CREATE INDEX IX_AuditEvent_Type ON dbo.DPromptShieldAuditEvent(EventType, CreatedAt DESC);
  `);

  console.log("schema-v2: enterprise DLP tables ensured");
}

// ---------------------------------------------------------------------------
// Groups — replace the old per-IP whitelist. A group is an exemption preset
// (which URLs / which classifications it exempts); a device is exempt when
// its IP is a member of a group. "General" is the built-in default group
// with no exemptions: every device that is in no other group counts as
// General, so General membership is implicit and never stored.
// ---------------------------------------------------------------------------
async function ensureGroupSchema(p) {
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldGroup')
    CREATE TABLE dbo.DPromptShieldGroup (
        Id              INT IDENTITY(1,1) PRIMARY KEY,
        Name            NVARCHAR(100)  NOT NULL,
        ExemptAllUrls   BIT            NOT NULL DEFAULT 0,
        ExemptAllTypes  BIT            NOT NULL DEFAULT 0,
        ExemptUrlsJson  NVARCHAR(MAX)  NULL,   -- JSON array, used when ExemptAllUrls = 0
        ExemptTypesJson NVARCHAR(MAX)  NULL,   -- JSON array of rule Types, used when ExemptAllTypes = 0
        IsSystem        BIT            NOT NULL DEFAULT 0,
        CreatedAt       DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME(),
        CreatedBy       NVARCHAR(50)   NULL
    );
  `);
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_DPromptShieldGroup_Name')
      CREATE UNIQUE INDEX UX_DPromptShieldGroup_Name ON dbo.DPromptShieldGroup(Name);
  `);
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DPromptShieldGroupMember')
    CREATE TABLE dbo.DPromptShieldGroupMember (
        Id        INT IDENTITY(1,1) PRIMARY KEY,
        GroupId   INT           NOT NULL REFERENCES dbo.DPromptShieldGroup(Id) ON DELETE CASCADE,
        ClientIp  NVARCHAR(45)  NOT NULL,
        AddedAt   DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
        AddedBy   NVARCHAR(50)  NULL
    );
  `);
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DPromptShieldGroupMember_ClientIp')
      CREATE INDEX IX_DPromptShieldGroupMember_ClientIp ON dbo.DPromptShieldGroupMember(ClientIp);
  `);
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_DPromptShieldGroupMember_Group_Ip')
      CREATE UNIQUE INDEX UX_DPromptShieldGroupMember_Group_Ip ON dbo.DPromptShieldGroupMember(GroupId, ClientIp);
  `);
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM dbo.DPromptShieldGroup WHERE IsSystem = 1)
      INSERT INTO dbo.DPromptShieldGroup (Name, IsSystem, CreatedBy) VALUES (N'General', 1, N'system');
  `);
  await migrateLegacyWhitelist(p);
}

// One-time, transactional carry-over of the old per-IP whitelist: entries
// with the same (URL, type) become one group, their IPs become its members,
// so every existing exemption keeps working. The old table is then renamed
// (not dropped) so this never runs twice and the data is still recoverable.
// If anything fails the transaction rolls back and it retries next start.
async function migrateLegacyWhitelist(p) {
  const has = await p.request().query(
    `SELECT COUNT(*) AS c FROM sys.tables WHERE name = 'DPromptShieldWhitelist'`);
  if (!has.recordset[0].c) return;

  const tx = new sql.Transaction(p);
  await tx.begin();
  try {
    const rq = () => new sql.Request(tx);
    const rows = (await rq().query(
      `SELECT ClientIp, UrlPattern, RuleType FROM dbo.DPromptShieldWhitelist WHERE (Enabled = 1 OR Enabled IS NULL)`
    )).recordset;

    const buckets = new Map();
    for (const r of rows) {
      const ip = (r.ClientIp || "").trim();
      if (!ip) continue;
      const url = (r.UrlPattern || "").trim() || null;
      const type = (r.RuleType || "").trim().toUpperCase() || null;
      const key = `${url || ""}|${type || ""}`;
      if (!buckets.has(key)) buckets.set(key, { url, type, ips: new Set() });
      buckets.get(key).ips.add(ip);
    }

    const used = new Set();
    for (const b of buckets.values()) {
      const base = `Legacy - ${b.url || "All URLs"} / ${b.type || "All classifications"}`.slice(0, 94);
      let name = base, n = 2;
      while (used.has(name.toLowerCase())) name = `${base} (${n++})`;
      used.add(name.toLowerCase());

      const g = rq();
      g.input("name", sql.NVarChar(100), name);
      g.input("allUrls", sql.Bit, b.url ? 0 : 1);
      g.input("allTypes", sql.Bit, b.type ? 0 : 1);
      g.input("urls", sql.NVarChar(sql.MAX), b.url ? JSON.stringify([b.url]) : null);
      g.input("types", sql.NVarChar(sql.MAX), b.type ? JSON.stringify([b.type]) : null);
      const ins = await g.query(`
        INSERT INTO dbo.DPromptShieldGroup (Name, ExemptAllUrls, ExemptAllTypes, ExemptUrlsJson, ExemptTypesJson, CreatedBy)
        OUTPUT INSERTED.Id
        VALUES (@name, @allUrls, @allTypes, @urls, @types, N'migration')
      `);
      const gid = ins.recordset[0].Id;
      for (const ip of b.ips) {
        const m = rq();
        m.input("gid", sql.Int, gid);
        m.input("ip", sql.NVarChar(45), ip.slice(0, 45));
        await m.query(`INSERT INTO dbo.DPromptShieldGroupMember (GroupId, ClientIp, AddedBy) VALUES (@gid, @ip, N'migration')`);
      }
    }

    await rq().query(`EXEC sp_rename N'dbo.DPromptShieldWhitelist', N'DPromptShieldWhitelist_legacy'`);
    await tx.commit();
    console.log(`groups: migrated ${rows.length} legacy whitelist entr${rows.length === 1 ? "y" : "ies"} into ${buckets.size} group(s); old table renamed to DPromptShieldWhitelist_legacy`);
  } catch (err) {
    try { await tx.rollback(); } catch (_) {}
    console.error("groups: legacy whitelist migration failed (rolled back, will retry next start):", err.message);
  }
}

// Exemption helpers shared by the incident POST and the extension policy sync.
const LOOPBACK_SQL = "('127.0.0.1', '::1', 'localhost')";
// Same device? Exact match, except the loopback aliases are treated as one
// machine (local testing shows up as either 127.0.0.1 or ::1).
function sameIpSql(a, b) {
  return `(TRIM(${a}) = TRIM(${b}) OR (TRIM(${a}) IN ${LOOPBACK_SQL} AND TRIM(${b}) IN ${LOOPBACK_SQL}))`;
}
function ipKey(ip) {
  const s = (ip || "").trim().toLowerCase();
  return ["127.0.0.1", "::1", "localhost"].includes(s) ? "loopback" : s;
}
function parseJsonList(s) {
  try {
    const a = JSON.parse(s || "[]");
    return Array.isArray(a) ? a.filter((x) => typeof x === "string" && x.trim()) : [];
  } catch (_) { return []; }
}

// Turns the groups an IP belongs to into the flat {UrlPattern, RuleType}
// entries the extension already understands (null = all). A group exempts
// the combinations of its URLs x its classifications; several groups simply
// add up. This is why the extension itself did not need to change.
async function getEffectiveExemptions(p, ip) {
  if (!ip || isLoopbackIp(ip)) return [];
  const r = p.request();
  r.input("ip", sql.NVarChar(45), ip);
  const res = await r.query(`
    SELECT g.Id, g.Name, g.ExemptAllUrls, g.ExemptAllTypes, g.ExemptUrlsJson, g.ExemptTypesJson
    FROM dbo.DPromptShieldGroupMember m
    JOIN dbo.DPromptShieldGroup g ON g.Id = m.GroupId
    WHERE ${sameIpSql("m.ClientIp", "@ip")}
  `);
  const seen = new Set();
  const out = [];
  for (const g of res.recordset) {
    if (seen.has(g.Id)) continue;
    seen.add(g.Id);
    const urls = g.ExemptAllUrls ? [null] : parseJsonList(g.ExemptUrlsJson);
    const types = g.ExemptAllTypes ? [null] : parseJsonList(g.ExemptTypesJson);
    for (const u of urls) for (const t of types) {
      out.push({ Id: null, ClientIp: ip, UrlPattern: u, RuleType: t, Notes: `Group: ${g.Name}` });
    }
  }
  return out;
}

// Called from the extension's periodic sync endpoints (monitored-urls,
// pii-rules) so the dashboard can show which devices actually have the
// extension installed and running — not just ones that triggered an
// incident. This is a passive check-in, not a live agent: "last seen"
// reflects the ~1 minute sync interval, not real-time presence.
async function recordDeviceCheckin(req) {
  try {
    const ip = getClientIp(req);
    // Loopback identifies the relay host, not a managed browser endpoint; do
    // not merge local clients into one IP-based device/exemption identity.
    if (!ip || isLoopbackIp(ip)) return;
    const p = await getPool();
    const r = p.request();
    r.input("ip", sql.NVarChar(45), ip);
    await r.query(`
      MERGE dbo.DPromptShieldDevice AS target
      USING (SELECT @ip AS ClientIp) AS src
      ON target.ClientIp = src.ClientIp
      WHEN MATCHED THEN UPDATE SET LastSeen = SYSUTCDATETIME(), CheckinCount = CheckinCount + 1
      WHEN NOT MATCHED THEN INSERT (ClientIp, FirstSeen, LastSeen, CheckinCount) VALUES (@ip, SYSUTCDATETIME(), SYSUTCDATETIME(), 1);
    `);
  } catch (err) {
    console.warn("device checkin failed:", err.message); // non-fatal, never block the real request
  }
}

// ---------------------------------------------------------------------------
// Incident logs
// ---------------------------------------------------------------------------

// IP address enrichment: classify the source, type, and confidence of an IP
// so the dashboard never misleadingly presents ::1 as a real endpoint IP.
// The client's real IP comes from the TCP connection itself — req.ip here
// (Express's own detection, which reads the raw socket by default) — NOT
// from anything the extension self-reports. This needs zero extension
// permissions and works identically on every browser. It only requires
// the relay to be directly reachable from the client (true on a plain LAN
// setup); once this sits behind a reverse proxy (IIS, nginx) later, that
// proxy must be configured to preserve/forward the original client IP.
function getClientIp(req) {
  return getRequestIp(req).ip;
}

function getEnrichedIp(req) {
  return getRequestIp(req);
}

// Generate a unique correlation ID for audit trail linkage
function generateCorrelationId() {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `COR-${ts}-${rand}`.toUpperCase();
}

app.post("/api/pii-logs", async (req, res) => {
  const validation = validateIncidentPayload(req.body);
  if (!validation.ok) return res.status(400).json({ error: validation.error });
  const e = validation.value;

  const enrichedIp = getEnrichedIp(req);
  const clientIp = enrichedIp.ip;
  const correlationId = generateCorrelationId();

  try {
    const p = await getPool();

    // Check if client IP is whitelisted for this site & findings
    if (clientIp) {
      const wlEntries = await getEffectiveExemptions(p, clientIp);
      if (wlEntries.length > 0) {
        const site = (e.site || "").toLowerCase();
        const unexemptedFindings = e.findings.filter(f => {
          return !wlEntries.some(w => {
            const urlOk = !w.UrlPattern || site.includes(w.UrlPattern.replace(/^https?:\/\//i, '').replace(/[\/*].*$/, '').toLowerCase());
            const typeOk = !w.RuleType || w.RuleType.toUpperCase() === (f.type || "").toUpperCase();
            return urlOk && typeOk;
          });
        });
        if (unexemptedFindings.length === 0) {
          return res.status(200).json({ ok: true, whitelisted: true });
        }
      }
    }

    // The extension currently sends a bare deviceId without a device-bound
    // credential. Do not resolve that claim to an approved enrollment or copy
    // its trusted ComputerName/EmployeeId: a caller could spoof another ID.
    // Keep the supplied label/employee ID as claims only; verified enrollment
    // requires a future proof-of-possession protocol (for example, a rotated
    // per-device secret or client certificate).
    const computerName = null;
    const resolvedDeviceId = null;

    const r = p.request();
    r.input("ts", sql.DateTime2, new Date(e.ts));
    r.input("site", sql.NVarChar(255), e.site || null);
    r.input("action", sql.NVarChar(50), e.action || "BLOCKED");
    r.input("promptLength", sql.Int, e.promptLength ?? null);
    r.input("findingsJson", sql.NVarChar(sql.MAX), JSON.stringify(e.findings));
    r.input("ip", sql.NVarChar(45), clientIp);
    r.input("ipSource", sql.NVarChar(20), enrichedIp.ipSource);
    r.input("ipType", sql.NVarChar(20), enrichedIp.ipType);
    r.input("ipConfidence", sql.NVarChar(10), enrichedIp.ipConfidence);
    r.input("employeeId", sql.NVarChar(100), e.employeeId || null);
    r.input("deviceLabel", sql.NVarChar(255), e.deviceLabel || null);
    r.input("computerName", sql.NVarChar(255), computerName);
    r.input("deviceId", sql.NVarChar(100), resolvedDeviceId);
    r.input("browserInfo", sql.NVarChar(500), e.browserInfo || null);
    r.input("correlationId", sql.NVarChar(50), correlationId);

    await r.query(`
      INSERT INTO dbo.DPromptShieldIncident
        (EventTs, SiteHost, ActionTaken, PromptLength, FindingsJson, ClientIp,
         IpSource, IpType, IpConfidence,
         EmployeeId, DeviceLabel, ComputerName, DeviceId, BrowserInfo, CorrelationId)
      VALUES
        (@ts, @site, @action, @promptLength, @findingsJson, @ip,
         @ipSource, @ipType, @ipConfidence,
         @employeeId, @deviceLabel, @computerName, @deviceId, @browserInfo, @correlationId)
    `);

    res.status(201).json({ ok: true, correlationId });
  } catch (err) {
    console.error("insert failed:", err.message);
    res.status(500).json({ error: "db insert failed" });
  }
});

function buildLogQuery(req, r) {
  const { site, type, employeeId, ip, from, to, action } = req.query;
  const where = [];
  if (site) { where.push("SiteHost = @site"); r.input("site", sql.NVarChar(255), site); }
  if (employeeId) { where.push("EmployeeId = @employeeId"); r.input("employeeId", sql.NVarChar(100), employeeId); }
  if (ip) { where.push("ClientIp = @ip"); r.input("ip", sql.NVarChar(45), ip); }
  if (from) { where.push("EventTs >= @from"); r.input("from", sql.DateTime2, new Date(from)); }
  if (to) { where.push("EventTs <= @to"); r.input("to", sql.DateTime2, new Date(to)); }
  if (action === "BLOCKED") {
    // Convenience grouping: every blocking variant, regardless of surface.
    where.push("ActionTaken IN ('BLOCKED', 'PASTE_BLOCKED', 'DROP_BLOCKED')");
  } else if (action === "MONITORED") {
    where.push("ActionTaken IN ('MONITORED', 'PASTE_MONITORED', 'DROP_MONITORED')");
  } else if (action) {
    where.push("ActionTaken = @action"); r.input("action", sql.NVarChar(50), action);
  }
  if (type) { where.push("FindingsJson LIKE @type"); r.input("type", sql.NVarChar(50), `%"type":"${type}"%`); }
  return where.length ? `WHERE ${where.join(" AND ")}` : "";
}

app.get("/api/pii-logs", async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 200, 1000);
  try {
    const p = await getPool();
    const r = p.request();
    r.input("limit", sql.Int, limit);
    const whereSql = buildLogQuery(req, r);
    const result = await r.query(`
      SELECT TOP (@limit) Id, EventTs, SiteHost, ActionTaken, PromptLength,
             FindingsJson, ClientIp, IpSource, IpType, IpConfidence,
             EmployeeId, DeviceLabel, ComputerName, DeviceId, BrowserInfo,
             CorrelationId, InsertedAt
      FROM dbo.DPromptShieldIncident
      ${whereSql}
      ORDER BY EventTs DESC
    `);
    const rows = result.recordset.map((row) => ({
      ...row,
      findings: JSON.parse(row.FindingsJson || "[]"),
      ipMeta: {
        source: row.IpSource || "unknown",
        type: row.IpType || "unknown",
        confidence: row.IpConfidence || "unavailable",
        isLoopback: (row.IpType || "").startsWith("loopback"),
      },
    }));
    res.json({ rows, count: rows.length });
  } catch (err) {
    console.error("query failed:", err.message);
    res.status(500).json({ error: "db query failed" });
  }
});

app.get("/api/pii-logs/export.csv", async (req, res) => {
  try {
    const p = await getPool();
    const r = p.request();
    r.input("limit", sql.Int, 50000);
    const whereSql = buildLogQuery(req, r);
    const result = await r.query(`
      SELECT TOP (@limit) Id, EventTs, SiteHost, ActionTaken, PromptLength,
             FindingsJson, ClientIp, IpSource, IpType, IpConfidence,
             EmployeeId, DeviceLabel, ComputerName, DeviceId, BrowserInfo,
             CorrelationId, InsertedAt
      FROM dbo.DPromptShieldIncident
      ${whereSql}
      ORDER BY EventTs DESC
    `);

    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const header = ["Id", "EventTs", "SiteHost", "ActionTaken", "PromptLength", "Findings",
      "ClientIp", "IpSource", "IpType", "IpConfidence",
      "EmployeeId", "DeviceLabel", "ComputerName", "DeviceId", "BrowserInfo",
      "CorrelationId", "InsertedAt"];
    const lines = [header.join(",")];
    for (const row of result.recordset) {
      const findings = JSON.parse(row.FindingsJson || "[]").map((f) => `${f.type}:${f.masked}`).join(" | ");
      lines.push([
        row.Id, row.EventTs?.toISOString?.() ?? row.EventTs, esc(row.SiteHost), row.ActionTaken,
        row.PromptLength, esc(findings), esc(row.ClientIp), esc(row.IpSource), esc(row.IpType),
        esc(row.IpConfidence), esc(row.EmployeeId), esc(row.DeviceLabel), esc(row.ComputerName),
        esc(row.DeviceId), esc(row.BrowserInfo), esc(row.CorrelationId),
        row.InsertedAt?.toISOString?.() ?? row.InsertedAt,
      ].join(","));
    }

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="DPromptShield-incidents-${Date.now()}.csv"`);
    res.send(lines.join("\n"));
  } catch (err) {
    console.error("export failed:", err.message);
    res.status(500).json({ error: "export failed" });
  }
});

// ---------------------------------------------------------------------------
// Monitored URLs
// ---------------------------------------------------------------------------

app.get("/api/monitored-urls", async (req, res) => {
  if (req.query.enabledOnly === "true") recordDeviceCheckin(req); // only count real extension polls, not dashboard admin calls
  try {
    const p = await getPool();
    const enabledOnly = req.query.enabledOnly === "true";
    const result = await p.request().query(`
      SELECT Id, Pattern, Enabled, CreatedAt FROM dbo.DPromptShieldMonitoredUrl
      ${enabledOnly ? "WHERE Enabled = 1" : ""}
      ORDER BY CreatedAt ASC
    `);
    res.json({ urls: result.recordset });
  } catch (err) {
    console.error("monitored-urls query failed:", err.message);
    res.status(500).json({ error: "db query failed" });
  }
});

app.post("/api/monitored-urls", async (req, res) => {
  let raw = (req.body?.pattern || "").trim();
  if (!raw) return res.status(400).json({ error: "pattern is required" });

  if (!/^https?:\/\//i.test(raw)) {
    raw = "https://" + raw;
  }
  raw = raw.replace(/\/+$/, "");
  if (!raw.endsWith("/*")) {
    raw = raw + "/*";
  }

  if (!/^https:\/\/(?:\*\.)?[a-zA-Z0-9.-]+(?:\/.*)?$/.test(raw)) {
    return res.status(400).json({ error: 'pattern must look like "https://example.com/*" or "https://*.example.com/*"' });
  }

  try {
    const p = await getPool();
    const patternsToInsert = [raw];
    const match = raw.match(/^https:\/\/([^/]+)(\/.*)$/i);
    if (match) {
      const host = match[1];
      const pathPart = match[2];
      if (!host.startsWith("*.") && !host.startsWith("www.")) {
        patternsToInsert.push(`https://*.${host}${pathPart}`);
      } else if (host.startsWith("www.")) {
        const rootHost = host.slice(4);
        patternsToInsert.push(`https://${rootHost}${pathPart}`);
        patternsToInsert.push(`https://*.${rootHost}${pathPart}`);
      }
    }

    for (const pat of patternsToInsert) {
      const r = p.request();
      r.input("pattern", sql.NVarChar(500), pat);
      await r.query(`
        IF NOT EXISTS (SELECT 1 FROM dbo.DPromptShieldMonitoredUrl WHERE Pattern = @pattern)
        INSERT INTO dbo.DPromptShieldMonitoredUrl (Pattern, Enabled) VALUES (@pattern, 1)
      `);
    }

    notifyPolicyChange("monitored-urls");
    res.status(201).json({ ok: true, patterns: patternsToInsert });
  } catch (err) {
    console.error("insert monitored url failed:", err.message);
    res.status(500).json({ error: "insert failed" });
  }
});


app.put("/api/monitored-urls/:id", async (req, res) => {
  let raw = (req.body?.pattern || "").trim();
  if (!raw) return res.status(400).json({ error: "pattern is required" });

  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
  raw = raw.replace(/\/+$/, "");
  if (!raw.endsWith("/*")) raw = raw + "/*";

  if (!/^https:\/\/(?:\*\.)?[a-zA-Z0-9.-]+(?:\/.*)?$/.test(raw)) {
    return res.status(400).json({ error: 'pattern must look like "https://example.com/*" or "https://*.example.com/*"' });
  }

  try {
    const p = await getPool();
    const r = p.request();
    r.input("id", sql.Int, Number(req.params.id));
    r.input("pattern", sql.NVarChar(500), raw);
    await r.query(`UPDATE dbo.DPromptShieldMonitoredUrl SET Pattern = @pattern WHERE Id = @id`);
    notifyPolicyChange("monitored-urls");
    res.json({ ok: true, pattern: raw });
  } catch (err) {
    console.error("update monitored url failed:", err.message);
    res.status(500).json({ error: "update failed" });
  }
});

app.patch("/api/monitored-urls/:id", async (req, res) => {
  try {
    const p = await getPool();
    const r = p.request();
    r.input("id", sql.Int, Number(req.params.id));
    r.input("enabled", sql.Bit, req.body?.enabled ? 1 : 0);
    await r.query(`UPDATE dbo.DPromptShieldMonitoredUrl SET Enabled = @enabled WHERE Id = @id`);
    notifyPolicyChange("monitored-urls");
    res.json({ ok: true });
  } catch (err) {
    console.error("update monitored url failed:", err.message);
    res.status(500).json({ error: "update failed" });
  }
});

app.delete("/api/monitored-urls/:id", async (req, res) => {
  try {
    const p = await getPool();
    const r = p.request();
    r.input("id", sql.Int, Number(req.params.id));
    await r.query(`DELETE FROM dbo.DPromptShieldMonitoredUrl WHERE Id = @id`);
    notifyPolicyChange("monitored-urls");
    res.json({ ok: true });
  } catch (err) {
    console.error("delete monitored url failed:", err.message);
    res.status(500).json({ error: "delete failed" });
  }
});

// ---------------------------------------------------------------------------
// PII detection rules — console-controlled, same pattern as monitored URLs.
// Pattern/flags are freely editable from the dashboard, no extension update
// needed. Validator/keyMode are limited to a small fixed whitelist the
// extension actually implements (see content.js) — not arbitrary code.
// Mode (block | monitor) is per rule and decided entirely here.
// ---------------------------------------------------------------------------

const VALID_VALIDATORS = ["none", "luhn", "nik"];
const VALID_KEYMODES = ["digits", "text"];
// Per-rule enforcement action. 'block' stops the send/paste/drop and logs
// BLOCKED; 'monitor' lets it through untouched and logs MONITORED only.
const VALID_MODES = ["block", "monitor"];

app.get("/api/pii-rules", async (req, res) => {
  const enabledOnly = req.query.enabledOnly === "true";
  if (enabledOnly) recordDeviceCheckin(req); // extension's own poll, counts as a check-in
  try {
    const p = await getPool();
    const result = await p.request().query(`
      SELECT Id, Type, Label, Pattern, Flags, Validator, KeyMode, Mode, Mode AS Action, Enabled, CreatedAt
      FROM dbo.DPromptShieldRule
      ${enabledOnly ? "WHERE Enabled = 1" : ""}
      ORDER BY CreatedAt ASC
    `);

    // When the extension polls, also return this device's exemptions (derived
    // from its group memberships). Field name kept as "whitelist" so already
    // deployed extensions keep working unchanged.
    let whitelist = [];
    if (enabledOnly) {
      whitelist = await getEffectiveExemptions(p, getClientIp(req));
    }

    res.json({ rules: result.recordset, whitelist, clientIp: getClientIp(req) });
  } catch (err) {
    console.error("pii-rules query failed:", err.message);
    res.status(500).json({ error: "db query failed" });
  }
});

app.post("/api/pii-rules", async (req, res) => {
  const { type, label, pattern, flags, validator, keyMode } = req.body || {};
  // frontend sends 'action', DB column is 'Mode' — accept either
  const modeRaw = req.body?.mode || req.body?.action;
  if (!type || !label || !pattern) {
    return res.status(400).json({ error: "type, label, and pattern are required" });
  }
  const v = validator || "none";
  const km = keyMode || "digits";
  const md = modeRaw || "block";
  if (!VALID_VALIDATORS.includes(v)) {
    return res.status(400).json({ error: `validator must be one of: ${VALID_VALIDATORS.join(", ")}` });
  }
  if (!VALID_KEYMODES.includes(km)) {
    return res.status(400).json({ error: `keyMode must be one of: ${VALID_KEYMODES.join(", ")}` });
  }
  if (!VALID_MODES.includes(md)) {
    return res.status(400).json({ error: `mode must be one of: ${VALID_MODES.join(", ")}` });
  }
  try {
    new RegExp(pattern, flags || "g"); // validate it compiles before storing
  } catch (err) {
    return res.status(400).json({ error: `invalid regex: ${err.message}` });
  }

  try {
    const p = await getPool();
    const r = p.request();
    r.input("type", sql.NVarChar(50), type.trim());
    r.input("label", sql.NVarChar(255), label.trim());
    r.input("pattern", sql.NVarChar(1000), pattern);
    r.input("flags", sql.NVarChar(10), flags || "g");
    r.input("validator", sql.NVarChar(20), v);
    r.input("keyMode", sql.NVarChar(10), km);
    r.input("mode", sql.NVarChar(10), md);
    await r.query(`
      INSERT INTO dbo.DPromptShieldRule (Type, Label, Pattern, Flags, Validator, KeyMode, Mode, Enabled)
      VALUES (@type, @label, @pattern, @flags, @validator, @keyMode, @mode, 1)
    `);
    notifyPolicyChange("pii-rules");
    res.status(201).json({ ok: true });
  } catch (err) {
    console.error("insert rule failed:", err.message);
    const isDup = /unique|duplicate/i.test(err.message);
    res.status(isDup ? 409 : 500).json({ error: isDup ? "a rule with this Type already exists" : "insert failed" });
  }
});

app.put("/api/pii-rules/:id", async (req, res) => {
  const { type, label, pattern, flags, validator, keyMode } = req.body || {};
  // frontend sends 'action', DB column is 'Mode' — accept either
  const mode = req.body?.mode || req.body?.action || null;
  if (pattern) {
    try {
      new RegExp(pattern, flags || "g");
    } catch (err) {
      return res.status(400).json({ error: `invalid regex: ${err.message}` });
    }
  }
  if (validator && !VALID_VALIDATORS.includes(validator)) {
    return res.status(400).json({ error: `validator must be one of: ${VALID_VALIDATORS.join(", ")}` });
  }
  if (keyMode && !VALID_KEYMODES.includes(keyMode)) {
    return res.status(400).json({ error: `keyMode must be one of: ${VALID_KEYMODES.join(", ")}` });
  }
  if (mode && !VALID_MODES.includes(mode)) {
    return res.status(400).json({ error: `mode must be one of: ${VALID_MODES.join(", ")}` });
  }
  try {
    const p = await getPool();
    const r = p.request();
    r.input("id", sql.Int, Number(req.params.id));
    r.input("type", sql.NVarChar(50), type ? type.trim() : null);
    r.input("label", sql.NVarChar(255), label ?? null);
    r.input("pattern", sql.NVarChar(1000), pattern ?? null);
    r.input("flags", sql.NVarChar(10), flags ?? null);
    r.input("validator", sql.NVarChar(20), validator ?? null);
    r.input("keyMode", sql.NVarChar(10), keyMode ?? null);
    r.input("mode", sql.NVarChar(10), mode ?? null);
    await r.query(`
      UPDATE dbo.DPromptShieldRule SET
        Type = COALESCE(@type, Type),
        Label = COALESCE(@label, Label),
        Pattern = COALESCE(@pattern, Pattern),
        Flags = COALESCE(@flags, Flags),
        Validator = COALESCE(@validator, Validator),
        KeyMode = COALESCE(@keyMode, KeyMode),
        Mode = COALESCE(@mode, Mode)
      WHERE Id = @id
    `);
    notifyPolicyChange("pii-rules");
    res.json({ ok: true });

  } catch (err) {
    console.error("update rule failed:", err.message);
    res.status(500).json({ error: "update failed" });
  }
});

app.patch("/api/pii-rules/:id", async (req, res) => {
  try {
    const p = await getPool();
    const r = p.request();
    r.input("id", sql.Int, Number(req.params.id));

    if (req.body?.action !== undefined) {
      // Toggle monitor / block action
      const action = req.body.action.toLowerCase() === "monitor" ? "monitor" : "block";
      r.input("mode", sql.NVarChar(20), action);
      await r.query(`UPDATE dbo.DPromptShieldRule SET Mode = @mode WHERE Id = @id`);
    } else {
      // Toggle enabled / disabled
      r.input("enabled", sql.Bit, req.body?.enabled ? 1 : 0);
      await r.query(`UPDATE dbo.DPromptShieldRule SET Enabled = @enabled WHERE Id = @id`);
    }

    notifyPolicyChange("pii-rules");
    res.json({ ok: true });
  } catch (err) {
    console.error("patch rule failed:", err.message);
    res.status(500).json({ error: "update failed" });
  }
});

app.delete("/api/pii-rules/:id", async (req, res) => {
  try {
    const p = await getPool();
    const r = p.request();
    r.input("id", sql.Int, Number(req.params.id));
    await r.query(`DELETE FROM dbo.DPromptShieldRule WHERE Id = @id`);
    notifyPolicyChange("pii-rules");
    res.json({ ok: true });
  } catch (err) {
    console.error("delete rule failed:", err.message);
    res.status(500).json({ error: "delete failed" });
  }
});

// ---------------------------------------------------------------------------
// Devices — passive check-in view for "manage extensions" on the dashboard
// ---------------------------------------------------------------------------

app.get("/api/devices", async (_req, res) => {
  try {
    const p = await getPool();
    const result = await p.request().query(`
      SELECT ClientIp, FirstSeen, LastSeen, CheckinCount
      FROM dbo.DPromptShieldDevice
      ORDER BY LastSeen DESC
    `);

    // Attach each device's groups. A device in no group is in "General".
    const gm = await p.request().query(`
      SELECT m.ClientIp, g.Id, g.Name
      FROM dbo.DPromptShieldGroupMember m
      JOIN dbo.DPromptShieldGroup g ON g.Id = m.GroupId
      ORDER BY g.Name
    `);
    const general = (await p.request().query(
      `SELECT TOP 1 Id, Name FROM dbo.DPromptShieldGroup WHERE IsSystem = 1`)).recordset[0];
    const byIp = new Map();
    for (const row of gm.recordset) {
      const k = ipKey(row.ClientIp);
      if (!byIp.has(k)) byIp.set(k, new Map());
      byIp.get(k).set(row.Id, { id: row.Id, name: row.Name });
    }
    const devices = result.recordset.map((d) => {
      const groups = byIp.get(ipKey(d.ClientIp));
      return {
        ...d,
        groups: groups && groups.size
          ? [...groups.values()]
          : [{ id: general?.Id ?? null, name: general?.Name ?? "General" }],
      };
    });
    res.json({ devices });
  } catch (err) {
    console.error("devices query failed:", err.message);
    res.status(500).json({ error: "db query failed" });
  }
});


// ---------------------------------------------------------------------------
// Group management. Any signed-in admin can create / edit groups and add or
// remove members; only the superadmin can delete a group. The built-in
// "General" group (IsSystem) cannot be edited, deleted or given members:
// it is simply every known device that is in no other group.
// ---------------------------------------------------------------------------

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function requireSuperadmin(req, res, next) {
  if (req.user?.role !== "superadmin") return res.status(403).json({ error: "Only the superadmin can delete a group." });
  next();
}

function isValidIp(s) {
  if (!s || s.length > 45) return false;
  if (s.toLowerCase() === "localhost") return true;
  const octet = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
  if (new RegExp(`^${octet}(\\.${octet}){3}$`).test(s)) return true;
  return s.includes(":") && /^[0-9a-fA-F:.]+$/.test(s);
}

function groupToApi(g) {
  return {
    id: g.Id,
    name: g.Name,
    isSystem: !!g.IsSystem,
    exemptAllUrls: !!g.ExemptAllUrls,
    exemptAllTypes: !!g.ExemptAllTypes,
    exemptUrls: parseJsonList(g.ExemptUrlsJson),
    exemptTypes: parseJsonList(g.ExemptTypesJson),
    createdAt: g.CreatedAt,
    createdBy: g.CreatedBy,
    memberCount: g.MemberCount ?? 0,
  };
}

// General's count = known devices that are in no other group.
const GROUP_SELECT = `
  SELECT g.Id, g.Name, g.ExemptAllUrls, g.ExemptAllTypes, g.ExemptUrlsJson, g.ExemptTypesJson,
         g.IsSystem, g.CreatedAt, g.CreatedBy,
         CASE WHEN g.IsSystem = 1
           THEN (SELECT COUNT(*) FROM dbo.DPromptShieldDevice d
                 WHERE NOT EXISTS (SELECT 1 FROM dbo.DPromptShieldGroupMember m WHERE ${sameIpSql("m.ClientIp", "d.ClientIp")}))
           ELSE (SELECT COUNT(*) FROM dbo.DPromptShieldGroupMember m WHERE m.GroupId = g.Id)
         END AS MemberCount
  FROM dbo.DPromptShieldGroup g
`;

async function parseGroupBody(p, body) {
  const b = body || {};
  const name = String(b.name ?? "").trim();
  if (!name) throw new HttpError(400, "Group name is required.");
  if (name.length > 100) throw new HttpError(400, "Group name must be 100 characters or fewer.");
  if (name.toLowerCase() === "general") throw new HttpError(400, '"General" is reserved for the default group.');

  const allUrls = !!b.exemptAllUrls;
  const allTypes = !!b.exemptAllTypes;
  const clean = (arr, max) => [...new Set((Array.isArray(arr) ? arr : [])
    .map((x) => String(x ?? "").trim()).filter((x) => x && x.length <= max))];
  const urls = allUrls ? [] : clean(b.exemptUrls, 500);
  let types = allTypes ? [] : clean(b.exemptTypes, 50);

  if (!allUrls && !urls.length) throw new HttpError(400, "Select at least one URL, or choose all URLs.");
  if (!allTypes && !types.length) throw new HttpError(400, "Select at least one classification, or choose all classifications.");

  if (types.length) {
    const known = new Map((await p.request().query(`SELECT Type FROM dbo.DPromptShieldRule`))
      .recordset.map((r) => [r.Type.toLowerCase(), r.Type]));
    const unknown = types.filter((t) => !known.has(t.toLowerCase()));
    if (unknown.length) throw new HttpError(400, `Unknown classification: ${unknown.join(", ")}`);
    types = types.map((t) => known.get(t.toLowerCase()));
  }
  return { name, allUrls, allTypes, urls, types };
}

function sendGroupError(res, err, what) {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  if (/duplicate|unique/i.test(err.message)) {
    return res.status(409).json({ error: "A group with this name already exists." });
  }
  console.error(`${what} failed:`, err.message);
  res.status(500).json({ error: `${what} failed` });
}

app.get("/api/groups", async (_req, res) => {
  try {
    const p = await getPool();
    const result = await p.request().query(`${GROUP_SELECT} ORDER BY g.IsSystem DESC, g.CreatedAt ASC, g.Id ASC`);
    res.json({ groups: result.recordset.map(groupToApi) });
  } catch (err) {
    sendGroupError(res, err, "groups query");
  }
});

app.get("/api/groups/:id", async (req, res) => {
  try {
    const p = await getPool();
    const id = Number(req.params.id);
    const r = p.request();
    r.input("id", sql.Int, id);
    const g = (await r.query(`${GROUP_SELECT} WHERE g.Id = @id`)).recordset[0];
    if (!g) throw new HttpError(404, "Group not found.");

    const LIMIT = 2000;
    let rows;
    if (g.IsSystem) {
      // Implicit members: devices that are in no other group.
      rows = (await p.request().query(`
        SELECT TOP (${LIMIT}) d.ClientIp, d.FirstSeen, d.LastSeen
        FROM dbo.DPromptShieldDevice d
        WHERE NOT EXISTS (SELECT 1 FROM dbo.DPromptShieldGroupMember m WHERE ${sameIpSql("m.ClientIp", "d.ClientIp")})
        ORDER BY d.LastSeen DESC
      `)).recordset.map((x) => ({ id: null, clientIp: x.ClientIp, addedAt: x.FirstSeen, addedBy: null, lastSeen: x.LastSeen }));
    } else {
      const r2 = p.request();
      r2.input("id", sql.Int, id);
      rows = (await r2.query(`
        SELECT TOP (${LIMIT}) m.Id, m.ClientIp, m.AddedAt, m.AddedBy, d.LastSeen
        FROM dbo.DPromptShieldGroupMember m
        LEFT JOIN dbo.DPromptShieldDevice d ON TRIM(d.ClientIp) = TRIM(m.ClientIp)
        WHERE m.GroupId = @id
        ORDER BY m.AddedAt DESC, m.Id DESC
      `)).recordset.map((x) => ({ id: x.Id, clientIp: x.ClientIp, addedAt: x.AddedAt, addedBy: x.AddedBy, lastSeen: x.LastSeen }));
    }
    res.json({
      group: groupToApi(g),
      members: rows,
      implicit: !!g.IsSystem,
      truncated: g.MemberCount > rows.length,
    });
  } catch (err) {
    sendGroupError(res, err, "group detail");
  }
});

app.post("/api/groups", async (req, res) => {
  try {
    const p = await getPool();
    const g = await parseGroupBody(p, req.body);
    const r = p.request();
    r.input("name", sql.NVarChar(100), g.name);
    r.input("allUrls", sql.Bit, g.allUrls ? 1 : 0);
    r.input("allTypes", sql.Bit, g.allTypes ? 1 : 0);
    r.input("urls", sql.NVarChar(sql.MAX), g.urls.length ? JSON.stringify(g.urls) : null);
    r.input("types", sql.NVarChar(sql.MAX), g.types.length ? JSON.stringify(g.types) : null);
    r.input("by", sql.NVarChar(50), req.user?.username || null);
    const ins = await r.query(`
      INSERT INTO dbo.DPromptShieldGroup (Name, ExemptAllUrls, ExemptAllTypes, ExemptUrlsJson, ExemptTypesJson, CreatedBy)
      OUTPUT INSERTED.Id
      VALUES (@name, @allUrls, @allTypes, @urls, @types, @by)
    `);
    res.status(201).json({ ok: true, id: ins.recordset[0].Id });
  } catch (err) {
    sendGroupError(res, err, "group create");
  }
});

app.put("/api/groups/:id", async (req, res) => {
  try {
    const p = await getPool();
    const id = Number(req.params.id);
    const cur = p.request();
    cur.input("id", sql.Int, id);
    const existing = (await cur.query(`SELECT IsSystem FROM dbo.DPromptShieldGroup WHERE Id = @id`)).recordset[0];
    if (!existing) throw new HttpError(404, "Group not found.");
    if (existing.IsSystem) throw new HttpError(400, "The General group cannot be edited.");

    const g = await parseGroupBody(p, req.body);
    const r = p.request();
    r.input("id", sql.Int, id);
    r.input("name", sql.NVarChar(100), g.name);
    r.input("allUrls", sql.Bit, g.allUrls ? 1 : 0);
    r.input("allTypes", sql.Bit, g.allTypes ? 1 : 0);
    r.input("urls", sql.NVarChar(sql.MAX), g.urls.length ? JSON.stringify(g.urls) : null);
    r.input("types", sql.NVarChar(sql.MAX), g.types.length ? JSON.stringify(g.types) : null);
    await r.query(`
      UPDATE dbo.DPromptShieldGroup
      SET Name = @name, ExemptAllUrls = @allUrls, ExemptAllTypes = @allTypes,
          ExemptUrlsJson = @urls, ExemptTypesJson = @types
      WHERE Id = @id
    `);
    notifyPolicyChange("groups");
    res.json({ ok: true });
  } catch (err) {
    sendGroupError(res, err, "group update");
  }
});

// Superadmin only. Members fall back to General automatically (cascade).
app.delete("/api/groups/:id", requireSuperadmin, async (req, res) => {
  try {
    const p = await getPool();
    const id = Number(req.params.id);
    const cur = p.request();
    cur.input("id", sql.Int, id);
    const existing = (await cur.query(`SELECT IsSystem FROM dbo.DPromptShieldGroup WHERE Id = @id`)).recordset[0];
    if (!existing) throw new HttpError(404, "Group not found.");
    if (existing.IsSystem) throw new HttpError(400, "The General group cannot be deleted.");
    const r = p.request();
    r.input("id", sql.Int, id);
    await r.query(`DELETE FROM dbo.DPromptShieldGroup WHERE Id = @id AND IsSystem = 0`);
    notifyPolicyChange("groups");
    res.json({ ok: true });
  } catch (err) {
    sendGroupError(res, err, "group delete");
  }
});

app.post("/api/groups/:id/members", async (req, res) => {
  try {
    const p = await getPool();
    const gid = Number(req.params.id);
    const raw = Array.isArray(req.body?.ips) ? req.body.ips : (req.body?.ip ? [req.body.ip] : []);
    const ips = [...new Set(raw.map((x) => String(x ?? "").trim()).filter(Boolean))];
    if (!ips.length) throw new HttpError(400, "Enter at least one IP address.");
    if (ips.length > 500) throw new HttpError(400, "Add at most 500 IP addresses at a time.");

    const cur = p.request();
    cur.input("id", sql.Int, gid);
    const g = (await cur.query(`SELECT IsSystem FROM dbo.DPromptShieldGroup WHERE Id = @id`)).recordset[0];
    if (!g) throw new HttpError(404, "Group not found.");
    if (g.IsSystem) throw new HttpError(400, "General membership is automatic: a device is in General until it is added to another group.");

    const invalid = [];
    let added = 0, skipped = 0;
    for (const ip of ips) {
      if (!isValidIp(ip)) { invalid.push(ip); continue; }
      const r = p.request();
      r.input("gid", sql.Int, gid);
      r.input("ip", sql.NVarChar(45), ip);
      r.input("by", sql.NVarChar(50), req.user?.username || null);
      const out = await r.query(`
        IF NOT EXISTS (SELECT 1 FROM dbo.DPromptShieldGroupMember WHERE GroupId = @gid AND ${sameIpSql("ClientIp", "@ip")})
        BEGIN
          INSERT INTO dbo.DPromptShieldGroupMember (GroupId, ClientIp, AddedBy) VALUES (@gid, @ip, @by);
          SELECT 1 AS added;
        END
        ELSE SELECT 0 AS added;
      `);
      if (out.recordset[0].added) added++; else skipped++;
    }
    if (!added && !skipped) {
      throw new HttpError(400, `Not a valid IP address: ${invalid.join(", ")}`);
    }
    if (added) notifyPolicyChange("groups");
    res.json({ ok: true, added, skipped, invalid });
  } catch (err) {
    sendGroupError(res, err, "add member");
  }
});

app.delete("/api/groups/:id/members/:memberId", async (req, res) => {
  try {
    const p = await getPool();
    const r = p.request();
    r.input("gid", sql.Int, Number(req.params.id));
    r.input("mid", sql.Int, Number(req.params.memberId));
    const out = await r.query(`DELETE FROM dbo.DPromptShieldGroupMember WHERE Id = @mid AND GroupId = @gid`);
    if (out.rowsAffected[0] > 0) notifyPolicyChange("groups");
    res.json({ ok: true });
  } catch (err) {
    sendGroupError(res, err, "remove member");
  }
});

const aiServices = require("./ai-services");
// ---------------------------------------------------------------------------
// Destination policy management and explainable policy evaluation.
// All routes require an authenticated console session via auth.apiGuard.
// A policy is never considered active until an administrator explicitly approves it.
// ---------------------------------------------------------------------------
async function writeAuditEvent(p, { eventType, actor, summary, details, correlationId }) {
  const r = p.request();
  r.input("eventType", sql.NVarChar(50), eventType);
  r.input("actor", sql.NVarChar(100), String(actor || "unknown").slice(0, 100));
  r.input("summary", sql.NVarChar(1000), String(summary || "").slice(0, 1000));
  r.input("details", sql.NVarChar(sql.MAX), JSON.stringify(details || {}));
  r.input("correlationId", sql.NVarChar(50), correlationId || null);
  await r.query(`INSERT INTO dbo.DPromptShieldAuditEvent (EventType, Actor, Summary, DetailsJson, CorrelationId)
                 VALUES (@eventType, @actor, @summary, @details, @correlationId)`);
}

app.get("/api/domain-policies", async (req, res) => {
  try {
    const p = await getPool();
    const r = p.request();
    const approvedOnly = req.query.approvedOnly === "true";
    const result = await r.query(`SELECT TOP (500) Id, Domain, Category, RiskLevel, Action, IsApproved, Notes, Source, LastUpdated, UpdatedBy
      FROM dbo.DPromptShieldDomainPolicy ${approvedOnly ? "WHERE IsApproved = 1" : ""} ORDER BY LastUpdated DESC, Domain ASC`);
    res.json({ policies: result.recordset });
  } catch (err) {
    console.error("domain policy list failed:", err.message);
    res.status(500).json({ error: "domain policy query failed" });
  }
});

app.post("/api/domain-policies", async (req, res) => {
  const validation = validateDomainPolicy(req.body);
  if (!validation.ok) return res.status(400).json({ error: validation.error });
  const policy = validation.value;
  try {
    const p = await getPool();
    const r = p.request();
    r.input("domain", sql.NVarChar(255), policy.domain);
    r.input("category", sql.NVarChar(50), policy.category);
    r.input("risk", sql.NVarChar(20), policy.riskLevel);
    r.input("action", sql.NVarChar(20), policy.action);
    r.input("notes", sql.NVarChar(sql.MAX), policy.notes || null);
    r.input("source", sql.NVarChar(50), policy.source);
    r.input("actor", sql.NVarChar(100), req.user.username);
    const result = await r.query(`
      MERGE dbo.DPromptShieldDomainPolicy AS target
      USING (SELECT @domain AS Domain) AS source ON target.Domain = source.Domain
      WHEN MATCHED THEN UPDATE SET Category=@category, RiskLevel=@risk, Action=@action, Notes=@notes, Source=@source,
        IsApproved=0, LastUpdated=SYSUTCDATETIME(), UpdatedBy=@actor
      WHEN NOT MATCHED THEN INSERT (Domain, Category, RiskLevel, Action, IsApproved, Notes, Source, LastUpdated, UpdatedBy)
        VALUES (@domain, @category, @risk, @action, 0, @notes, @source, SYSUTCDATETIME(), @actor)
      OUTPUT inserted.Id, inserted.Domain, inserted.Category, inserted.RiskLevel, inserted.Action, inserted.IsApproved, inserted.LastUpdated;`);
    const saved = result.recordset[0];
    await writeAuditEvent(p, { eventType: "domain_policy_saved", actor: req.user.username, summary: `Destination policy saved for ${policy.domain}; approval reset`, details: { domain: policy.domain, action: policy.action, riskLevel: policy.riskLevel, approved: false } });
    notifyPolicyChange("domain-policies");
    res.status(201).json({ ok: true, policy: saved, requiresApproval: true });
  } catch (err) {
    console.error("domain policy save failed:", err.message);
    res.status(500).json({ error: "domain policy save failed" });
  }
});

app.post("/api/domain-policies/:id/approve", async (req, res) => {
  const id = Number(req.params.id);
  const notes = typeof req.body?.notes === "string" ? req.body.notes.trim().slice(0, 1000) : "";
  if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid policy ID." });
  try {
    const p = await getPool();
    const r = p.request();
    r.input("id", sql.Int, id);
    r.input("actor", sql.NVarChar(100), req.user.username);
    const result = await r.query(`UPDATE dbo.DPromptShieldDomainPolicy SET IsApproved=1, LastUpdated=SYSUTCDATETIME(), UpdatedBy=@actor OUTPUT inserted.Id, inserted.Domain, inserted.Category, inserted.RiskLevel, inserted.Action, inserted.IsApproved, inserted.LastUpdated WHERE Id=@id`);
    if (!result.recordset.length) return res.status(404).json({ error: "Domain policy not found." });
    const policy = result.recordset[0];
    await writeAuditEvent(p, { eventType: "domain_policy_approved", actor: req.user.username, summary: `Destination policy approved for ${policy.Domain}`, details: { policyId: id, domain: policy.Domain, action: policy.Action, notes } });
    notifyPolicyChange("domain-policies");
    res.json({ ok: true, policy });
  } catch (err) {
    console.error("domain policy approval failed:", err.message);
    res.status(500).json({ error: "domain policy approval failed" });
  }
});

app.delete("/api/domain-policies/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid policy ID." });
  try {
    const p = await getPool();
    const r = p.request(); r.input("id", sql.Int, id);
    const result = await r.query(`DELETE FROM dbo.DPromptShieldDomainPolicy OUTPUT deleted.Domain, deleted.Action WHERE Id=@id`);
    if (!result.recordset.length) return res.status(404).json({ error: "Domain policy not found." });
    await writeAuditEvent(p, { eventType: "domain_policy_deleted", actor: req.user.username, summary: `Destination policy deleted for ${result.recordset[0].Domain}`, details: { domain: result.recordset[0].Domain, action: result.recordset[0].Action } });
    notifyPolicyChange("domain-policies");
    res.json({ ok: true });
  } catch (err) {
    console.error("domain policy delete failed:", err.message);
    res.status(500).json({ error: "domain policy delete failed" });
  }
});

app.post("/api/policy/evaluate", async (req, res) => {
  const domain = normalizeDomain(req.body?.domain);
  if (!domain) return res.status(400).json({ error: "Provide a valid destination domain or http(s) URL." });
  const category = typeof req.body?.dataCategory === "string" ? req.body.dataCategory.slice(0, 80) : "unknown";
  const unknownDomainAction = req.body?.unknownDomainAction === "block" ? "block" : "monitor";
  try {
    const p = await getPool();
    const r = p.request(); r.input("domain", sql.NVarChar(255), domain);
    const lookup = await r.query(`SELECT TOP 1 Id, Domain, Category, RiskLevel, Action, IsApproved FROM dbo.DPromptShieldDomainPolicy WHERE Domain=@domain`);
    const result = evaluatePolicy({ domain, dataCategory: category, policy: lookup.recordset[0] || null, unknownDomainAction });
    const correlationId = generateCorrelationId();
    await writeAuditEvent(p, { eventType: "policy_evaluated", actor: req.user.username, correlationId, summary: `${domain}: ${result.decision} (${result.reason})`, details: { domain, dataCategory: result.dataCategory, decision: result.decision, reason: result.reason, policyId: result.policyId, destinationRisk: result.destinationRisk } });
    res.json({ ...result, correlationId, enforced: false, notice: "This endpoint evaluates and audits a decision. Browser/network enforcement is not implied unless the caller applies this decision before submission." });
  } catch (err) {
    console.error("policy evaluation failed:", err.message);
    res.status(500).json({ error: "policy evaluation failed" });
  }
});

app.get("/api/ai/status", (_req, res) => res.json({ geminiConfigured: aiServices.configured(), model: aiServices.model, firestoreAuditConfigured: Boolean(process.env.FIREBASE_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT) && process.env.FIRESTORE_AUDIT_ENABLED !== "false" }));
app.post("/api/ai/classify-regulation", (req, res, next) => Promise.resolve(aiServices.classifyRegulation(req, res)).catch(next));
app.post("/api/ai/analyze-url", (req, res, next) => Promise.resolve(aiServices.analyzeUrl(req, res)).catch(next));
app.post("/api/ai/inspect-content", (req, res, next) => Promise.resolve(aiServices.inspectContent(req, res)).catch(next));
app.use((err, req, res, _next) => {
  console.error(`AI/API error ${req.method} ${req.path}:`, err.message);
  if (res.headersSent) return;
  res.status(Number(err.status) || 500).json({ error: Number(err.status) === 503 ? err.message : "Request failed. Check service configuration and logs." });
});

app.get("/api/health", (_req, res) => res.json({ ok: true }));


const port = process.env.PORT || 4000;
ensureSchema()
  .then(() => auth.ensureAuthSchema())
  .then(() => app.listen(port, () => console.log(`DPromptShield listening on http://localhost:${port}`)))
  .catch((err) => {
    console.error("failed to initialize schema:", err.message);
    process.exit(1);
  });
