# DPromptShield implementation audit

Audit based on the repository source inspected on 2026-10-18. This workspace is not a Git repository, so tracked/committed status could not be established. No database connection or external AI call was made during discovery.

## Repository and stack

- `dpromptshield_server_v1.0.4/`: Node.js (package requires >=22), Express 4, `mssql`/SQL Server; monolithic routes and schema initialization in `server.js`; auth in `auth.js`; Gemini/optional Firestore REST in `ai-services.js`; static vanilla HTML in `public/`.
- `dpromptshield_extension_v1.0.4/`: Chrome Manifest V3 service worker and dynamically registered content script. Firefox manifest and Safari/browser notes also exist. The runtime relay is currently hard-coded as `http://localhost:4000` in both extension scripts.
- Database: `DPromptShieldDB` is the example/configured database name, not verified as reachable. `server.js` creates and incrementally alters tables at startup; `schema.sql` is a commented reference, not the migration runner.
- Testing: no test framework or test files existed at audit start. `npm run check` passed for the server's existing JS entry points. No SQL Server availability was tested.
- Root HTML `ai-lab.html` duplicates `public/ai-lab.html`; the served copy is under `public/`.

## Actual data path

1. Extension service worker polls `/api/monitored-urls?enabledOnly=true` and `/api/pii-rules?enabledOnly=true`, stores rules in extension local storage, and registers `content.js` for matching URLs. SSE requests trigger another sync.
2. Content script scans editor text plus paste/drop content with configured regex and fixed NIK/Luhn validators. It prevents prompt send/paste/drop for `block`; `monitor` leaves data untouched and logs a finding. It does not mask or intercept file upload. Send protection is DOM/event based and is not a universal guarantee for every SPA or request path.
3. The content script sends an event to the MV3 worker. Worker obtains optional managed `employeeId`/`deviceLabel`, keeps up to 500 events locally, and POSTs `/api/pii-logs`. Findings currently contain masked examples, not prompt body. Retries are periodic but event identity is timestamp-based and not server-idempotent.
4. Express persists incidents in `dbo.DPromptShieldIncident`; dashboard fetches `/api/pii-logs`, renders rows and CSV. Admin console routes are protected by in-memory sessions; extension routes are selectively public.

## Feature status (verified from code, not labels)

| Area | Status | Evidence / limitation |
|---|---|---|
| Regex detection and NIK/Luhn validation | Implemented | Server rules sync to content script; five defaults. |
| Prompt/paste/drop block or monitor | Partial | DOM/event listeners; no masking, upload hook, or guarantee against app-specific alternate submission paths. |
| Incident storage/list/export | Implemented with gaps | SQL writes and dashboard read; public event endpoint lacks authentication/rate limiting/idempotency. |
| IP attribution | Partial; corrected in this change | Prior code used request IP but called it verified and broad string checks misclassified some addresses. Relay observes connection/proxy source, not necessarily endpoint. |
| User/device identity | Partial/unverified | Managed employee/device label only; `deviceId` request field is not cryptographically bound to an enrolled endpoint. No reliable Windows hostname API in extension. |
| Admin authentication | Implemented, deployment caveats | scrypt and in-memory sessions; session invalidation on restart; login limiter is process-local. RBAC is mostly `admin`/`superadmin`. |
| Policy sync | Implemented | URL/rule CRUD and SSE. Legacy rules only support `block`/`monitor`. |
| Audit trail | Partial | Incident SQL events and SQL audit table exist; AI audit to Firestore is optional and failures are explicitly non-fatal. No unified approval/policy audit lifecycle. |
| AI Security Lab | Advisory only | Gemini classifies pasted text, analyzes a URL, and inspects submitted text/image. These user-provided contents are sent to Gemini; results are not persisted as proposals. No upload ingestion or RAG. |
| RAG/governance | Schema only | Document/proposal tables are created, but no upload, extraction, chunking, retrieval, proposal, review, or activation APIs/UI were found. |
| Domain exfiltration control | Schema only/not enforced | Domain policy table exists; no domain policy routes/engine or threat intelligence adapter found. Gemini URL advisor is not reputation and does not enforce. |
| Upload masking | Not implemented | AI lab image inspector is advisory; extension has no upload interception. |
| Dashboard analytics | Partial | Displays client IP and event-derived summaries; no policy coverage/approval/masking effectiveness backed by data. |

## Root causes and security findings

1. `::1` is the TCP loopback observed when client and relay connect locally. It is not a laptop address. A browser extension cannot reliably obtain a machine hostname or endpoint IP using the APIs present here. Behind NAT/hosting proxy, the relay may observe a network/proxy address instead.
2. Before this change, `classifyIp()` used prefix/colon checks, labeled every non-loopback address `verified`, and did not validate with an IP parser. It did not honor configured trusted proxy hops. The schema already had nullable attribution fields, but `IpConfidence NVARCHAR(10)` was too short for `unavailable`; startup now widens it additively to `NVARCHAR(20)`.
3. Loopback check-ins previously became a shared IP-keyed device and could match IP-based group exemptions. New loopback check-ins are skipped and loopback addresses never receive group exemptions. Existing legacy rows are not deleted.
4. Device enrollment schema exists, but incident ingestion looks up client-supplied `deviceId` without proof of possession. It must not be treated as verified identity.
5. Several enterprise tables already existed in `ensureSchemaV2`; absence of the features is missing orchestration/routes/UI, not missing table names.
6. `cors({ origin: true })` reflects arbitrary origins. Changing this requires enumerating approved extension/AI origins or a different worker-mediated fetch architecture; current extension content scripts fetch directly from monitored pages.
7. Backend `.env` exists and contains values for secrets (values intentionally not reproduced here). Treat any real credentials in it as exposed: rotate/revoke them and remove the file from any published artifact/history through the owner's secret-handling process. No credentials were read or changed in this audit.
8. AI endpoints can send supplied text/image to the configured Gemini provider. The UI discloses this; do not submit regulated/secret data without organizational approval. Gemini API errors/timeouts are surfaced as request failures, but provider error text may include detail in server logs.
9. `ensureSchema()` correctly gates `listen()` on schema and auth initialization and exits non-zero on failure. It is startup DDL rather than versioned migration management and requires schema privileges.
10. The extension origin is hard-coded to local HTTP in both scripts, conflicting with deployment guidance and preventing consistent configuration. No extension test harness exists.

## Initial baseline

- Baseline before this iteration: backend `npm run check` PASS; backend tests 4/4 PASS; extension lifecycle tests 3/3 PASS.
- After this iteration: backend `npm run check` PASS; backend `npm test` PASS (10/10); extension lifecycle tests PASS (3/3). The new tests cover exact CORS origin matching and incident payload validation. SQL Server integration, database migration execution, and browser E2E were not run.
- The initial combined extension check ended with an expected missing `.env` path error from its unrelated env-name listing; extension syntax/JSON checks passed separately in final verification.
- Database/AI end-to-end tests: not run; SQL credentials/services and explicit permission to invoke external AI are unavailable/not requested.


## Additional hardening implemented in this iteration (2026-10-18)

- Replaced reflected arbitrary-origin CORS with an exact origin allowlist. The default matches the Chrome extension ID derived from the public key in the included manifest; deployments using a different extension key or cross-origin console must explicitly set `CORS_ALLOWED_ORIGINS`. Requests without an Origin header remain usable for non-browser clients.
- Added server-side validation and normalization for incident timestamps, action values, hostnames, finding count/content, and prompt length. Unknown fields such as a raw prompt are not copied into the normalized incident object.
- Stopped resolving a client-supplied bare `deviceId` into an approved enrollment's trusted hostname. The current extension protocol has no proof-of-possession, so a submitted ID alone is not sufficient evidence of device identity. `ComputerName` and resolved `DeviceId` remain unavailable until device-bound authentication is implemented. Extension-supplied employee ID/device label values remain claims, not verified identity; downstream UI must not present them as authoritative.
- Added unit tests for the above behaviors. These changes do not implement RAG ingestion, policy approval/publishing, domain enforcement, pre-submit masking, or file watermarking; those remain future phases requiring connected workflows and integration tests.


## Additional destination policy foundation (2026-10-18)

- Added `policy-engine.js` for deterministic domain normalization, input validation, sensitivity-aware decisions, approval requirements, risk precedence, and explainable evidence.
- Added authenticated domain policy CRUD and explicit approval endpoints in `server.js`. New or edited policies are unapproved by default. An allow action is not effective until approved.
- Added an authenticated policy evaluation endpoint that writes an audit event and returns `enforced: false` to make the boundary explicit. The browser extension does not yet call this endpoint and its decisions are not enforced on network submission.
- Offline policy-engine tests pass. SQL Server execution and API integration against a real database were not run.
