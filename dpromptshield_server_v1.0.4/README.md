# DPromptShield Enterprise AI DLP (AI Builder Cup)

DPromptShield is a browser-extension-led data-loss-prevention prototype with an admin console, configurable detection policies, incident monitoring, and Gemini-powered policy/content advisory tools. The existing extension and SQL-backed policy engine are retained.

## Extension relay configuration

Before testing the browser extension against Cloud Run, replace `https://REPLACE_WITH_CLOUD_RUN_HOST` with the actual HTTPS hostname in both extension `background.js` and `content.js`, then load the unpacked extension. The included legacy CRX is excluded from the submission package because it can target a previous internal relay. The private extension signing key is not distributed.

## AI Security Lab

After logging in, open `/ai-lab.html` or use the Admin Console link. The AI Lab provides:

- **Regulation-to-Policy:** sends pasted regulation text to Gemini and proposes classifications. Outputs require human review and are not automatically activated as enforcement rules.
- **URL Risk Advisor:** recommends allow/monitor/block from the hostname and context supplied. It is not a live URL crawler, threat-intelligence feed, or reputation scanner; unknown domains should default to monitor pending review.
- **Content/Image Inspector:** sends pasted text or PNG/JPEG/WebP to Gemini for advisory classification/visual text extraction. It does not intercept arbitrary browser file uploads, rewrite files, or enforce masking in the extension.
- **Firestore audit:** writes only summarized event metadata (event type, actor, summary, timestamp); it is best-effort and does not store raw prompt/file content.

## Required integrations

- **Gemini:** set `GEMINI_API_KEY` in Secret Manager / environment. Model defaults to `gemini-2.5-flash`. Requests send supplied text/image to Google's Gemini API. Use synthetic data for demos.
- **Firebase / Firestore:** set `FIREBASE_PROJECT_ID` (or `GOOGLE_CLOUD_PROJECT`) and enable Firestore. The Cloud Run service account needs the least-privilege IAM role needed to create documents in the configured database. No service-account JSON key should be committed.
- **Cloud Run:** Dockerfile targets Node.js 22 and listens on `PORT` (Cloud Run sets it to 8080). The existing SQL Server database is still required by the current server startup and authentication/policy system. Configure `DB_*` securely and ensure Cloud Run can reach SQL Server (private IP via VPC connector/VPC egress, or an approved secured endpoint). A deploy will fail at startup if SQL Server is unreachable.

## Local setup

1. Copy `.env.example` to `.env` and fill in valid SQL Server credentials, `GEMINI_API_KEY`, and initial admin passwords if the admin table is empty. Never commit `.env`.
2. Ensure the database user has permissions to create/use the required DPromptShield tables, or run the provided `schema.sql` with a DBA.
3. Run `npm ci`, `npm run check`, then `npm start`.
4. Sign in to the existing admin console, then open `/ai-lab.html`.

Initial account passwords are no longer hard-coded. If `dbo.DPromptShieldAdmin` is empty, startup requires `INITIAL_SUPERADMIN_PASSWORD` and `INITIAL_ADMIN_PASSWORD` (12+ characters); store them in Secret Manager or a local ignored `.env`. Existing populated admin tables are unchanged.

## Cloud Run deployment checklist

1. Enable Cloud Run, Cloud Build, Artifact Registry, Secret Manager, Firestore, and Gemini API access as applicable.
2. Create secrets `GEMINI_API_KEY`, `DPROMPTSHIELD_DB_PASSWORD`, and initial admin passwords if the admin table is empty; grant the Cloud Run runtime service account `secretmanager.secretAccessor`.
3. Initialize Firestore and grant the runtime service account required Firestore access.
4. Configure `DB_SERVER`, `DB_PORT`, `DB_DATABASE`, `DB_USER`, `DB_ENCRYPT`, `DB_TRUST_SERVER_CERT` as Cloud Run environment variables and configure secure network connectivity to SQL Server.
5. Review `cloudbuild.yaml` before running `gcloud builds submit --config cloudbuild.yaml .`. The sample enables unauthenticated ingress for a demo; use an appropriate access gateway/IAM for enterprise use.
6. Verify `/api/health`, login, `/api/ai/status`, Firestore audit writes, policy sync, incident ingestion, and the extension on a clean browser profile.

The sample uses `asia-southeast2`; adjust for your project. Before deploying, edit the placeholder `DB_SERVER=CHANGE_ME_SQL_HOST` and `DB_USER=CHANGE_ME_SQL_USER` values in `cloudbuild.yaml` to match your SQL Server. It does not provision SQL Server, Firestore, secrets, or networking automatically.

## API endpoints (admin session required except existing extension endpoints)

- `GET /api/ai/status` — integration status
- `POST /api/ai/classify-regulation` — `{ "title": "UU PDP", "text": "..." }`
- `POST /api/ai/analyze-url` — `{ "url": "https://example.com", "context": "..." }`
- `POST /api/ai/inspect-content` — `{ "text": "..." }` or `{ "image": { "mimeType": "image/png", "data": "BASE64" } }`

## Important security and prototype limitations

- AI recommendations are probabilistic. Require admin approval; do not auto-block or auto-allow domains solely from a model answer.
- The extension covers supported input/paste/drop/send paths on configured sites; it is not a universal OS-level DLP agent and cannot guarantee inspection of every file upload or every website.
- File/image inspector is an admin demo endpoint, not a universal upload interceptor. Enterprise-wide file DLP needs browser-specific upload interception where supported and/or an endpoint/network DLP agent, plus file-type parsing, OCR, archive handling, and enforcement.
- Existing SQL Server remains authoritative for core incidents, policies, groups, and admin accounts. Firestore currently receives AI event summaries, not a wholesale migration of existing SQL data.
- The AI Lab sends submitted text/images to Gemini. Use synthetic data unless your organization has approved the processing. Masking is only an AI recommendation in the inspector; no original file is modified.
- The extension CRX signing private key is excluded from this source package. Keep it securely offline/in a secret store.

## Submission checklist

- [ ] Deploy and verify an accessible prototype URL.
- [ ] Publish sanitized source; verify no `.env`, passwords, private keys, DB dumps, or production logs.
- [ ] Configure Gemini and Firestore and demonstrate both in the video.
- [ ] Demonstrate a synthetic blocked prompt, regulation classification, URL advisory, and image/text inspection.
- [ ] Record a 3–4 minute video and verify duration.
- [ ] Fill in team details and links in the prescribed pitch deck.

---

## Existing extension and console documentation

The existing DPromptShield extension, SQL-backed admin console, configurable PII rules, monitored URL policies, group exemptions, incident logs, and CSV export are retained. The original documentation below remains relevant to those features.

# AIPII Guard — server (relay + dashboard + signing key)

This is the half that stays on your machine — database connection, the
dashboard, and the extension's private signing key (`signing-key/`, keep
that safe). The extension itself lives in a separate `aipii_guard_extension`
folder, which is the only thing meant to be copied to other machines.

---

Receives incident logs from the extension and writes them to MSSQL. No
local agent anywhere in this version — **the relay itself reads the
client's real IP directly off the incoming connection** (`getClientIp()`
in `server.js`) when the extension posts an incident. This needs no
browser API and works identically on every browser.

(An earlier draft tried having the extension self-report its IP via
`chrome.system.network`, which turned out to be a deprecated Chrome Apps
API not available to regular extensions — this server-side approach is
the corrected, simpler, more reliable design.)

## Quick start
```
npm install
cp .env.example .env   # fill in your DB details
npm start
```
Expect: `aipii_guard relay listening on http://localhost:4000`

Dashboard: http://localhost:4000/dashboard.html (root `/` redirects here; you'll be asked to sign in)

## Console login & admin accounts
The dashboard and every admin API sit behind a login (`/login.html`). Two roles:

| Role | Can do |
|------|--------|
| **Super Admin** | Everything an admin can, plus add / delete admins (the **Admins** tab). Cannot be deleted. |
| **Admin** | Everything in the console except managing admins. |

Every account — including the superadmin — can change **its own** password
from the header (*Change Password*). Nobody can change anyone else's.

**First run** seeds two accounts into `dbo.DPromptShieldAdmin` (only when the
table is empty): `superDPromptShield` (superadmin) and `adminDLP` (admin). The
seed values are in `DEFAULT_ACCOUNTS` at the top of `auth.js`. Change both
passwords after first login — once the table has rows, `auth.js` never reseeds,
so the passwords written in that file stop mattering.

- Passwords are stored as salted scrypt hashes, never plaintext.
- Sessions are 8 hours, kept in server memory (HttpOnly, SameSite=Strict
  cookie). Restarting the relay signs everyone out. Deleting an admin or
  changing a password signs out that account's other sessions immediately.
- 5 failed logins for one username+IP locks that pair for 15 minutes; 20 from
  one IP locks the IP.
- Password rule: 8–128 characters with at least one letter and one number.
- Serving the console over HTTPS (e.g. behind IIS/nginx)? Set
  `COOKIE_SECURE=true` in `.env` so the session cookie is HTTPS-only.

**Endpoints that stay open (no login)** — these are what the extension itself
calls, so they must work without credentials:
`POST /api/pii-logs`, `GET /api/policy-stream`,
`GET /api/monitored-urls?enabledOnly=true`, `GET /api/pii-rules?enabledOnly=true`,
`GET /api/health`. Everything else under `/api` requires a session.

**Forgot the superadmin password?** On the server machine:
```
node reset-password.js superDPromptShield "NewPassw0rd"
```
then restart the relay.

## Database
`server.js` auto-creates `dbo.AipiiGuardIncident` and
`dbo.AipiiGuardMonitoredUrl` on first run if they don't exist, and seeds
the default monitored-site list. See `schema.sql` for the explicit DDL if
you'd rather create these deliberately on a shared/production database.

## Monitored URLs — console-controlled
The dashboard's "Monitored URLs" panel is the only source of truth for what
the extension watches. Every installed extension polls
`GET /api/monitored-urls?enabledOnly=true` every 5 minutes and re-registers
its content script to match exactly that list — nothing inside the
extension itself can change it.

## PII detection rules — console-controlled, same pattern as monitored URLs
`dbo.AipiiGuardRule` holds the regex patterns the extension actually runs,
seeded on first run with the original NIK/NPWP/CREDIT_CARD/PHONE_ID/EMAIL
rules. The dashboard's "PII Detection Rules" panel can add, edit (via
`PUT`), enable/disable, and delete rules — every extension picks up the
change within ~5 minutes, no update needed.

### Block vs Monitor — per rule

Every rule carries an enforcement `Mode`:

- **Block** (`block`) — the default, and what every rule did before this
  column existed. The extension stops the paste/drop/send, shows the red
  toast, and logs `BLOCKED` / `PASTE_BLOCKED` / `DROP_BLOCKED`.
- **Monitor** (`monitor`) — the prompt goes through completely untouched.
  Nothing is prevented and no toast appears, but the incident is still
  logged as `MONITORED` / `PASTE_MONITORED` / `DROP_MONITORED`, so it shows
  up in the console's incident table and in the CSV export.

Set it per rule: the Action toggle in the "PII Detection Policies" table,
or the "Enforcement Action" field when adding/editing a rule.

Example: leave NIK on **Block**, add a US SSN rule on **Monitor** — typing
an Indonesian ID number still blocks the send, while SSNs pass through and
every occurrence is recorded for review.

The dashboard's incident filters have an **Action** dropdown to separate
the two (All / Blocked / Monitored / the six exact actions).

`Mode` lives in `dbo.AipiiGuardRule.Mode`. An existing database gets the
column added automatically on the next server start, and every rule
already in it stays on `block`.

**Important boundary**: `Pattern`/`Flags` are free-form and apply
immediately. `Validator`/`KeyMode` are restricted to a small fixed set the
extension actually implements (`none`/`luhn`/`nik` for validator,
`digits`/`text` for keyMode) — this is deliberate. Letting the server push
arbitrary executable validation logic into the extension would mean a
compromised database could run arbitrary code in every user's browser;
restricting it to data (regex) plus a whitelist of pre-approved validators
avoids that. A genuinely new validation algorithm (say, a passport-number
checksum) needs an actual `content.js` code change and redeploy — same
kind of platform limit as the Firefox/Safari IP notes elsewhere.

## Connected Devices — passive check-in, not a live agent
Every time an extension polls `/api/monitored-urls` or `/api/pii-rules`
(its normal 5-minute sync, not something added on purpose for this), the
server records that IP's check-in time. The dashboard's "Connected Devices"
panel surfaces this as a rough "which machines have the extension running"
view. It is NOT real-time presence — "Last Seen" can lag up to 5 minutes
behind the device going offline, and it says nothing about whether the
extension is actually enabled in the user's browser vs. just installed.

## CSV export
`GET /api/pii-logs/export.csv` — same filters as the dashboard table,
uncapped up to 50k rows.

## Identity fields
- `ClientIp` — captured server-side from the TCP connection on every
  incident POST, no extension setup needed. Only accurate when the relay
  is reached directly (true for local/LAN testing); once behind a reverse
  proxy, configure `X-Forwarded-For` trust (see `server.js` comments).
- `EmployeeId` / `DeviceLabel` — optional, only populated if you push them
  via `chrome.storage.managed` (enterprise policy / GPO). Entirely
  independent of IP capture; skip this if you don't need it.

## Groups (exemptions) — replaces the per-IP whitelist
A **group** is an exemption preset: which URLs and which classifications it
exempts. A device is exempt when its IP is a **member** of a group, so
granting an exemption means adding the IP to a group instead of configuring
URL and type rule by rule.

- **General** is the built-in default group (no exemptions). It is implicit:
  every known device that is in no other group counts as General. It cannot
  be edited, deleted, or given members.
- Create e.g. **VIP** with "all URLs" + "all classifications" to exempt
  everything. Otherwise pick specific URLs and classifications; a group
  exempts where a chosen URL AND a chosen classification both match.
- A device can be in several groups; exemptions add up. Removing it from
  every group returns it to General.
- Any admin can create/edit groups and add/remove members. **Only the
  superadmin can delete a group** (also enforced by the API, 403 otherwise).
- Activity of exempt devices is still processed as before: a prompt whose
  findings are all exempt is let through and not logged as an incident.

API (all need a console login): `GET/POST /api/groups`,
`GET/PUT/DELETE /api/groups/:id`, `POST /api/groups/:id/members`
(`{ips: [...]}`), `DELETE /api/groups/:id/members/:memberId`.
`GET /api/devices` now includes each device's `groups`.

**No extension change is needed.** The server turns a device's groups into
the same `whitelist` entries (`UrlPattern`, `RuleType`, null = all) it already
returned from `/api/pii-rules?enabledOnly=true`, and pushes a `policy-change`
event on every group change so open extensions re-sync immediately.

**Upgrading:** replace `server.js`, `public/dashboard.html` and `schema.sql`,
then restart. On first start the existing whitelist rows are copied into
groups named `Legacy - <url> / <type>` (so nobody loses an exemption) and the
old table is renamed `DPromptShieldWhitelist_legacy`. Review those groups and
merge them into proper ones (e.g. VIP) when convenient.

## Dashboard filters
Every table section has a filter bar: pick a column (or All columns), type a
value, and tick **Exact match** to require the whole value. Computed columns
(Total Syncs, Total Member) are not searchable. Incident Logs keeps its own
server-side filters.

## Session timeout (idle sign-out)
An admin who is inactive for **15 minutes** must sign in again. Change it with
`SESSION_IDLE_MINUTES` in `.env` (unset, zero, negative or non-numeric values
fall back to 15, so a typo cannot disable it). The existing 8-hour absolute
limit still applies on top.

- **What counts as activity:** real input in the console (mouse, keyboard,
  scroll, touch), reported by a small heartbeat (`POST /api/auth/activity`),
  plus any state-changing request. The dashboard's automatic refreshing and
  `/api/auth/me` deliberately do **not** count, otherwise an unattended
  console would never time out.
- **Enforced on the server**, so closing the tab, a frozen tab, or a sleeping
  laptop all still expire on schedule. The next request gets a 401 and the
  browser lands on the login page with an "inactivity" notice.
- **Warning popup:** 60 seconds before the limit the console asks "Are you
  still there?" with **Stay signed in** / **Sign out now**. Moving the mouse
  or pressing Escape does not dismiss it. With several tabs open, activity in
  any of them keeps all of them signed in.
- A server restart still signs everyone out (sessions are in memory).


## Destination policy API (admin session required)

This iteration adds a deterministic destination-policy foundation. All endpoints below require an authenticated console session:

- `GET /api/domain-policies` — list saved policies.
- `POST /api/domain-policies` — create/update a policy. Body: `{"domain":"example.com","category":"ai_assistant","riskLevel":"high","action":"require_approval","notes":"Business review required"}`. Saving always resets approval to false.
- `POST /api/domain-policies/:id/approve` — explicitly approve a saved policy. Optional body: `{"notes":"Reviewed by security administrator"}`.
- `DELETE /api/domain-policies/:id` — remove a policy.
- `POST /api/policy/evaluate` — body: `{"domain":"example.com","dataCategory":"internal","unknownDomainAction":"monitor"}`. Returns an explainable decision and correlation ID and records an audit event.

**Enforcement boundary:** the evaluation API is currently an authenticated console/demo API and returns `enforced: false`. The browser extension does not yet consume these decisions before submitting content. Do not present domain blocking as active endpoint enforcement until that integration and browser E2E verification are completed.
