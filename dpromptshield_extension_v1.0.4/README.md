# AIPII Guard — extension only

This folder is the extension by itself — no server code, no database
credentials, nothing sensitive. Safe to copy, zip, or upload as-is to any
other machine, or hand to someone else to load.

It does NOT run standalone — it needs a running AIPII Guard server (the
`aipii_guard_server` folder) to push incident logs to and pull its PII
detection rules + monitored-URL list from.

## Before loading this on a new machine

Open `background.js` and check this line near the top:
```js
const RELAY_ORIGIN = "https://REPLACE_WITH_CLOUD_RUN_HOST";
```
- If the server runs on the SAME machine as this extension → leave as-is.
- If the server runs elsewhere on your network (e.g. your main PC acting
  as the server, and this extension loaded on a different test PC) →
  change this to that machine's real IP, e.g.:
  ```js
  const RELAY_ORIGIN = "https://REPLACE_WITH_CLOUD_RUN_HOST";
  ```
  and make sure `manifest.json`'s `host_permissions` includes that same
  address (add `"https://REPLACE_WITH_CLOUD_RUN_HOST/*"` alongside the localhost
  entry).

## Loading it

1. `chrome://extensions` → enable Developer mode → **Load unpacked** →
   select this `aipii_guard_extension` folder.
2. Confirm the extension ID shown matches `dekohbbgboflmeikbohfokimiojiioci`
   (it should, automatically — the fixed signing key is already baked into
   `manifest.json`, no separate key file needed here).
3. Open the server's dashboard (wherever it's running) and confirm this
   new device starts showing up under "Connected Devices" within a few
   minutes.

See `BROWSERS.md` for Edge/Firefox, `SAFARI.md` for Safari.


## Configure the deployed relay before testing

Before loading this extension, replace `https://REPLACE_WITH_CLOUD_RUN_HOST` with the exact HTTPS hostname of your deployed Cloud Run service in both `background.js` and `content.js`. Then load the extension unpacked from this folder. Do not use the included legacy CRX from older packages; it may point at an internal/private relay address. The private signing key is intentionally not included.

## Policy sync and extension reload

On monitored AI pages, prompt submission stays blocked until the content script
has received a valid, fresh policy response. If the relay or service worker is
unavailable, the extension makes at most three short policy retries, then waits
for connectivity/page visibility recovery; it does not trust a cached whitelist
after a failed sync. If Chrome reports that the extension context was
invalidated during an extension reload, the old tab context stops extension API
calls and remains fail-closed. Reload the affected page after the extension has
restarted to create a fresh content-script context.

Policy requests are sent through the MV3 service worker (not directly from the
ChatGPT page), avoiding page-origin CORS restrictions. In Chrome, check the
extension's **Service worker** console on `chrome://extensions` if the content
script reports that no message receiver exists.
