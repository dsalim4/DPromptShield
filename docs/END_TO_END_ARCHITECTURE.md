# DPromptShield end-to-end architecture (observed)

## Existing runtime path

```text
Admin browser
  -> Express static console + cookie session (auth.js)
  -> SQL Server (policy CRUD, incidents, admin accounts)
  -> in-process SSE notification

Managed browser / MV3 extension
  -> background.js polls URL/rule APIs and registers content.js
  -> content.js scans prompt editor + paste/drop events locally
  -> on block/monitor, LOG message -> background.js
  -> POST /api/pii-logs -> Express -> DPromptShieldIncident
  -> dashboard GET /api/pii-logs -> rendered incident table/CSV

Admin AI Lab
  -> authenticated /api/ai/* -> Gemini (submitted text/image is external)
  -> optional summarized metadata to Firestore REST
```

The extension currently supports a fixed localhost relay origin. Device labels and employee IDs may come from managed storage. The server can observe its TCP peer IP; this may be loopback, a LAN address, NAT egress, or proxy. It cannot infer a Windows hostname from the current extension APIs.

## Existing data stores

- SQL Server tables are ensured by startup DDL in `server.js` and `auth.js`: incidents, monitored URLs, PII rules, device check-ins, groups/members, device enrollments, policy documents/proposals, domain policies, masking sessions, audit events, admins.
- The latter enterprise tables are schema only unless routes/services described in source actually use them. In particular, policy document/proposal, domain policy and masking session tables do not make RAG, approval, reputation, or masking operational.
- Optional Firestore audit from `ai-services.js` stores summaries, not raw input by design. Its failure is non-fatal.

## Trust boundaries and observed controls

- Console APIs require an in-memory admin session except explicit public routes and extension policy polls. Session cookie is HttpOnly/SameSite=Strict; `Secure` depends on `COOKIE_SECURE`.
- Extension incident and policy endpoints are public to support unmanaged browser installs; event body/device identity therefore cannot establish a cryptographic device identity. SQL parameterization is used in inspected writes.
- The extension's detector executes locally and does not send raw prompt text in its incident event; AI Lab requests do send user-submitted content to Gemini.
- CORS currently reflects origins. Extension content scripts perform direct cross-origin relay requests, so an allowlist requires enumerating target origins or moving those requests behind the extension worker.
- Proxy headers are not trusted by default. This implementation adds optional explicit proxy trust using `TRUSTED_PROXY_IPS` and reports source/confidence metadata; it does not claim the result is always an endpoint IP.

## Target workflow (not yet end-to-end implemented)

```text
Admin reference document upload
 -> validate/store/hash/extract/version/chunk
 -> evidence retrieval with source/section citations
 -> schema-validated proposal + test vectors (AI output untrusted)
 -> admin review/revise/reject/approve with audit
 -> immutable approved policy version + controlled activation
 -> authenticated/versioned extension policy sync
 -> local detection + domain/category policy evaluation
 -> pre-submission block or verified masking adapter
 -> sanitized/idempotent event with correlation + policy version
 -> SQL incident/audit -> dashboard investigation and revision loop
```

This target requires a safe file parser, policy version API, reviewer authorization, extension adapter coverage and request-level proof. A document/policy table, advisory Gemini response, or DOM text change alone is not sufficient. Cross-device exfiltration requires additional identity/file/cloud/agent telemetry; absent those signals, events must be labeled suspected rather than confirmed.

## IP attribution semantics

- `ClientIp`: normalized numeric address observed on the accepted network path; absent/invalid values are null.
- `IpSource`: `connection`, `trusted-proxy`, or `unknown`.
- `IpType`: loopback/private/link-local/public IPv4 or IPv6, or unknown.
- `IpConfidence`: `observed` means a numeric address was observed, not that it identifies a laptop. `unavailable` means no valid address was available.
- X-Forwarded-For is only considered through Express after the immediate proxy matches configured trusted proxy IP/CIDR values. Never replace loopback with guessed/server IP.

## Operational dependencies

SQL Server reachability and valid DB secrets are required for server startup. Gemini and Google credentials are optional for the existing advisory lab. Browser + extension deployment and a configured relay origin are required for extension enforcement. No SQL, Gemini, Firestore, or browser E2E test was run in this implementation environment.
