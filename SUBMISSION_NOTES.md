# AI Builder Cup — DPromptShield Submission Notes

**Challenge fit:** Future of Work & Enterprise Productivity; secondary fit: BFSI Intelligent Risk, Fraud & Financial Experiences.

**Pitch:** DPromptShield is an AI-assisted enterprise DLP layer that detects sensitive data in employee prompts, lets security teams manage enforcement centrally, and uses Gemini to turn privacy policies into reviewable classification suggestions.

**Technology mapping:** Firebase project identity + Firestore audit sink; Cloud Run containerized Node.js API; Gemini for regulation classification, URL risk advice and text/image inspection; existing SQL Server remains authoritative for current policies, incidents, groups and admin accounts.

**Do not overclaim:** No universal upload blocking, fully on-prem AI, automatic legal compliance, live URL reputation scan, or automatic file masking. The AI Lab is an advisory prototype; comprehensive browser file upload interception and on-prem model hosting remain future work.

## Suggested 3:30 video flow
1. 0:00–0:25 problem and architecture.
2. 0:25–1:00 synthetic NIK/email prompt blocked by extension; show masked incident.
3. 1:00–1:45 paste a short synthetic UU PDP/GDPR excerpt into Regulation-to-Policy; explain human approval.
4. 1:45–2:15 analyze a sample AI URL and show risk/action/limitations.
5. 2:15–2:50 inspect synthetic text or image with fake PII.
6. 2:50–3:15 show Firestore summary event and privacy boundary.
7. 3:15–3:30 closing and links.

## Pitch deck template outline
1. Team Details — fill team name/leader; problem: sensitive data leaks into public AI tools.
2. Brief about the idea — DPromptShield AI DLP.
3. Opportunities — employee generative AI use and fragmented prompt-level controls.
4. Features — prompt detection, block/monitor, central rules, URL advice, regulation classification, image/text inspection, incident audit.
5. Process flow — user action → extension detector → policy decision → allow/block/monitor → masked incident → admin review; AI path: regulation text → Gemini → suggested categories → human approval.
6. Wireframes — console, extension popup, AI Security Lab.
7. Architecture — browser extension → Cloud Run Node.js → SQL Server core policy/incident/auth; Gemini API; Firestore summary audit.
8. Technologies — JavaScript extension, Node.js/Express, SQL Server, Cloud Run, Gemini API, Firebase/Firestore.
9. Estimated cost — optional; use measured project-specific numbers only.
10. Prototype snapshots — add actual screenshots after deployment.
11. Performance report — report only measured latency, detection rate and false positives from real tests.
12. Future — endpoint DLP, comprehensive file parsing/OCR, on-prem model option, SIEM/SOAR integration, policy approval workflow.
13. Links — public GitHub repository, 3–4 minute demo, deployed prototype.
