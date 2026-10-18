# DPromptShield AI Builder Cup — Submission Readiness

Updated: 2026-10-18

## What is demonstrable in this package

1. Existing browser extension prompt/paste/drop PII detection with configured `block`/`monitor` modes (coverage is limited to supported page/editor paths).
2. Existing incident dashboard and IP provenance fields.
3. New authenticated Destination Policy page at `/domain-policy.html`.
4. New SQL-backed destination policy lifecycle: create/update as pending, explicit approval, delete, deterministic evaluate, and audit event.
5. Unit tests for IP attribution, CORS policy, incident validation, and destination policy logic.

## Important honest limitations

- Domain policy evaluation is not wired into the extension's pre-submit path. The API explicitly returns `enforced: false`; the page also displays this boundary.
- The existing AI Security Lab is advisory. The package does not yet provide complete secure document upload, OCR/text extraction, persistent chunk indexing, RAG retrieval, verified citations, or a publish-approved regulatory rule lifecycle.
- Device enrollment does not yet prove possession of a device-bound credential; extension-provided device labels are claims, not verified endpoint identity.
- Automatic masking before external submission, upload interception, format-aware file transformation, and watermarking are not production implemented.
- SQL Server integration, Gemini external calls, deployed Cloud Run, and real-browser end-to-end tests were not run in this build environment.

## Local verification

From `dpromptshield_server_v1.0.4` using Node.js 22+:

```powershell
npm ci
npm run check
npm test
```

Also validate the extension JavaScript syntax and JSON manifests. Configure the database and secrets using a private `.env` file or deployment secret manager. Do not package `.env` or API keys.

## Suggested hackathon demo sequence

1. Sign in to the admin console.
2. Open AI Security Lab and show advisory classification with synthetic, non-sensitive example data.
3. Open Destination Policy.
4. Add `example.com` with category `ai_assistant`, risk `high`, action `require_approval`.
5. Show it remains pending approval after saving.
6. Approve it and run Evaluate with `internal` data; show decision, policy reference, reason, correlation ID, and audit outcome.
7. Evaluate an unknown destination and `restricted` data to demonstrate monitor-by-default and high-sensitivity blocking logic.
8. Explain that the destination decision API is a demonstrator and is not yet enforcing the browser's network submission. Do not claim it blocks a real upload.

## Before publishing

- Rotate any credentials that were present in earlier working copies or shared archives.
- Ensure `.env`, service-account JSON, certificates, and API keys are not included in the submission artifact.
- Confirm the deployed API URL, CORS origin, cookie security settings, SQL Server reachability, and secret bindings in the actual target environment.
- Do not call the project production-ready until the incomplete integrations above have been implemented and tested.
