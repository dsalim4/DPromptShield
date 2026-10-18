# DPromptShield implementation plan

Plan derived from the source audit in `IMPLEMENTATION_AUDIT.md`. P0/P1 IP attribution is being implemented first; higher-risk/external-processing changes remain gated on architecture and deployment dependencies.

## Phased work

| Priority | Root cause / work | Likely files | Database/API/extension/UI | Security, risks and tests | Acceptance |
|---|---|---|---|---|---|
| P0 | No test harness; permissive CORS; secret-bearing local env; startup DDL | `package.json`, `server.js`, config/docs | Add offline unit tests; decide explicit CORS origins; rotate/remove exposed secrets operationally; consider versioned non-destructive migrations | CORS allowlist risks breaking content-script cross-origin fetch; never commit/reprint `.env`; SQL Server required for startup | Baseline checks pass, CORS is explicit for deployed origins, startup failure remains visible |
| P1 | IP source misrepresented; endpoint identity unavailable/unverified | `ip-attribution.js`, `server.js`, `.env.example`, dashboard, enrollment/auth design | Existing attribution columns are reused; additive startup migration widens `IpConfidence` for `unavailable`; optional `TRUSTED_PROXY_IPS` | Exact configured trusted hops only; test IPv4, IPv6, mapped IPv4, invalid, loopback, trusted/untrusted proxy | Never invent IP/hostname; confidence describes observation, unknown stays unavailable |
| P1 next | Device identity currently trusts bare client-supplied device ID | Extension background, enrollment API/schema, admin UI | Authenticated enrollment/credential proof needed; schema exists | Do not trust hostname/device ID alone; approve enrollment and bind secret/device/user; tests for forged IDs | Unknown devices explicitly unknown; approved identity verifiably bound |
| P2 | No action engine for allow/warn/mask/approval; prompt payload replacement is not reliable across supported SPAs | New policy/masking modules, content/background, policy APIs, dashboard | Versioned approved policy distribution and safe event schema | Local detector only; fail closed where required; prove outbound payload replacement for each adapter; do not log raw text | Raw sensitive values absent from outbound request under tested adapters, otherwise blocked |
| P2 uploads | No upload interception | Extension adapters and parser pipeline | Initially declare supported formats only after safe parser and replacement flow exist | File size/type validation, parser isolation, original unchanged; synthetic fixtures | Network request carries transformed file, otherwise required categories blocked |
| P3 | AI Lab advisory output not persisted; RAG tables unused | `ai-services.js`, server routes, SQL migration, AI Lab UI | Secure document upload/storage, extraction/chunks/citations, proposal lifecycle endpoints and audit | External provider transfer needs explicit approval; untrusted docs/prompt injection; no automatic activation | Proposal carries source citations and cannot publish without authorized reviewer |
| P4 | Domain table has no policy enforcement/reputation implementation | Domain module, server API, UI, extension | Domain normalization, internal destination policy, optional vetted reputation adapter | Never send content/full URLs externally; cache/timeout/failure behavior; unknown is policy-driven | Deterministic destination + data-category decision with audit |
| P5 | No unified workflow/idempotency/metrics | API, SQL, extension, dashboard | Correlation key, dedupe constraint, workflow health and backed metrics | Transaction boundaries and limited retries; avoid reporting suspected transfer as confirmed | Approved policy -> extension -> pre-send enforcement -> persisted correlated incident verified |

## Changes implemented in this iteration

- Added pure IP normalization/classification and request attribution in `dpromptshield_server_v1.0.4/ip-attribution.js`.
- Forwarded IPs are used only when `TRUSTED_PROXY_IPS` explicitly configures trusted Express proxy hops; otherwise the immediate socket address is used. Source confidence is `observed`, not `verified` endpoint identity.
- Existing `DPromptShieldIncident` attribution columns are reused; an idempotent additive startup migration widens old `IpConfidence` columns from NVARCHAR(10) to NVARCHAR(20). It has not been run against a database in this environment.
- Dashboard labels the value as observed source IP and marks loopback as not endpoint IP.
- Added Node built-in unit tests and `npm test` script.

## API and database approach

- Preserve existing `/api/pii-logs`, `/api/pii-rules`, and schema names for backward compatibility.
- Any future schema change must be an additive, idempotent migration with old incident rows remaining nullable. Do not reset production DB.
- Admin approval/publish endpoints must require an explicit permission, persist reviewer/time/reason, keep immutable policy versions, and audit both approval/rejection. AI/service account cannot approve.
- Extension retrieval must expose only active approved policy versions, pinned/versioned and fail closed if required policy is stale/unavailable.

## Test plan and dependencies

- Offline: `npm run check`, `npm test`, extension JS syntax checks; pure modules for IP, domain, detector, masker and policy decisions.
- SQL integration: requires configured reachable SQL Server and a disposable/test database; avoid migration against production until reviewed.
- AI/RAG: requires a specifically approved provider, API credentials, synthetic documents, and explicit authorization to transmit content externally.
- Browser E2E: requires supported browser, unpacked extension and controlled test AI destination; capture requests to prove raw values do not leave.
- Each acceptance claim in final status must map to a completed test, not UI presence or HTTP 200 alone.


## Iteration update — 2026-10-18

Completed in this workspace:
- Exact CORS origin allowlist via `CORS_ALLOWED_ORIGINS`; defaults to the extension origin derived from the packaged manifest public key.
- `incident-validation.js` validates and normalizes incident input before database persistence, with bounded fields and no copying of unknown/raw prompt fields.
- Bare extension-supplied device IDs are no longer resolved to trusted enrollment identity because the existing protocol does not prove device possession.
- Added unit tests for CORS policy and incident validation.

Remaining blockers: device enrollment proof-of-possession; secure document upload/extraction/chunking/retrieval; persisted AI proposal/reviewer/publish lifecycle; domain-policy integration with extension decisions; verified pre-submit masking and upload transformation; format-specific watermarking; SQL Server and browser end-to-end validation.


## Iteration update — 2026-10-18 (destination policy foundation)

Implemented in this workspace:
- Added `policy-engine.js`, a deterministic, testable policy evaluator that normalizes DNS destinations, requires explicit approval before a saved policy can allow traffic, treats unknown destinations as monitor by default (or block when explicitly configured), blocks `restricted`/credential/financial/high-sensitivity categories, and overrides permissive decisions for critical-risk domains.
- Added authenticated SQL-backed API routes: `GET /api/domain-policies`, `POST /api/domain-policies`, `POST /api/domain-policies/:id/approve`, `DELETE /api/domain-policies/:id`, and `POST /api/policy/evaluate`.
- Saving/updating a domain policy resets `IsApproved=0`; approval is a separate action. Save, approve, delete, and evaluation outcomes are written to `DPromptShieldAuditEvent` with bounded operational metadata, not raw prompts.
- Added offline unit tests for domain normalization, invalid inputs, unknown/unapproved behavior, high-risk precedence, and explainable policy results.

Important boundary:
- `POST /api/policy/evaluate` evaluates and audits a decision but explicitly returns `enforced: false`. It is not yet wired into extension pre-submit flow, so do not describe this iteration as live domain blocking.
- SQL-backed routes were syntax-checked only; no SQL Server integration test ran in this environment. The existing startup DDL creates the required tables, but a deployment must verify the SQL Server schema and permissions.
- RAG ingestion, document chunk persistence/retrieval, proposal review/publish UI, device proof-of-possession, browser-side pre-submit masking, upload interception, and watermarking remain incomplete.
