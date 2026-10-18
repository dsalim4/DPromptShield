# Loading AIPII Guard in each browser

The extension logic (content.js, background.js, popup.js) is shared across
all browsers unchanged — Firefox implements the same `chrome.*` API as an
alias, callback-style, so no code fork is needed there. Only the manifest
differs. There is no local agent to install anywhere in this version —
one less moving part per browser compared to the old pii-guard package.

## Chrome
1. chrome://extensions
2. Enable "Developer mode"
3. "Load unpacked" → select the `aipii_guard` folder (uses `manifest.json`)
4. Check the ID shown matches `dekohbbgboflmeikbohfokimiojiioci` (see
   `deploy/EXTENSION_ID.md`) — it should, every time, thanks to the fixed
   signing key already embedded in `manifest.json`.

## Edge (Chromium-based — identical to Chrome)
1. edge://extensions
2. Enable "Developer mode"
3. "Load unpacked" → select the `aipii_guard` folder, same manifest

## Firefox
Needs its own manifest (`manifest.firefox.json`) — explicit ID,
`"scripts"` instead of `"service_worker"` for the background page.
```
cp -r aipii_guard aipii_guard-firefox
cd aipii_guard-firefox
rm manifest.json
mv manifest.firefox.json manifest.json
```
Then `about:debugging#/runtime/this-firefox` → "Load Temporary Add-on…" →
select `manifest.json`.

**IP detection on Firefox**: identical to Chrome/Edge — the relay server
reads the client's real IP from the connection itself (see README.md's
"How IP detection works" section), not from anything the extension
reports. No browser-specific API involved, so there's no Firefox
limitation here at all.

## Safari
See `SAFARI.md`. Simpler now than before — no agent means nothing extra to
wrap or distribute alongside the extension itself. IP detection works the
same way as every other browser here too, server-side, with no
Safari-specific caveat.

## Which sites get monitored
Controlled entirely from the console's "Monitored URLs" panel — see the
main README. Nothing in any manifest lists specific sites anymore.
