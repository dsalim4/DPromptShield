# Disclaimer!!!!!!!
This md file is not updated. It is still a template for testing, further configuration is required!!!
This extension is not (yet) compatible for Safari.

# Getting AIPII Guard into Safari

Safari requires a native macOS app wrapper built with Xcode — this step
needs a Mac and can't be done from this environment.

## 1. Prerequisites
- A Mac with Xcode installed.
- Safari 16.4+ for Manifest V3 / `chrome.scripting` support (this
  extension relies on `chrome.scripting.registerContentScripts` for
  console-controlled site monitoring).

## 2. Convert
```
xcrun safari-web-extension-converter /path/to/aipii_guard --app-name "AIPII Guard"
```
Use the Chrome/Edge manifest folder (`manifest.json`), not the Firefox one.

## 3. Build and run
Open the generated `.xcodeproj` in Xcode, run it, then in Safari:
**Settings → Extensions** → enable "AIPII Guard". You may need
**Settings → Advanced → Show features for web developers**, then
**Develop → Allow Unsigned Extensions** while testing.

## 4. Known caveats
- **Dynamic content script registration**: same caveat as before — test
  whether `chrome.scripting.registerContentScripts` actually activates
  sites added via the console on your Safari version before relying on it.
- **IP detection**: not a concern here — the relay server reads the
  client's IP from the connection itself, not from any browser API, so
  this works the same on Safari as everywhere else.

## 5. Distribution
Internal testing: the Xcode-built app runs locally. Org-wide: notarize and
distribute via Apple Business Manager / MDM (e.g. Jamf). Public: Mac App
Store submission, subject to Apple review.
