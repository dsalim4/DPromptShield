# Fixed extension ID for AIPII Guard

## What was generated
- `extension-signing-key.pem` (this folder) — the private key. Keep safe,
  out of version control / shared drives.
- The matching public key is embedded in `manifest.json`'s `"key"` field.

## The resulting fixed ID
```
dekohbbgboflmeikbohfokimiojiioci
```
Permanent for this extension on Chrome/Edge, as long as `manifest.json`'s
`"key"` field stays unchanged — same ID on every machine, every time,
whether loaded unpacked, packed into a `.crx`, or force-installed via GPO.

## What this means for rollout
`local-agent`'s `.env` no longer exists in this version at all — there's no
per-machine agent config to keep in sync anymore. The fixed ID mainly
matters now for GPO `ExtensionSettings` force-install policies (which
target a specific extension ID) and for anything server-side that might
want to recognize "requests genuinely came from our extension" in the
future.

## This is a NEW key, different from the old pii-guard package
If you also still have the earlier `pii-guard` extension installed
anywhere, note its ID (`icheildfoacogbfniipbpfgiloogldjp`) is unrelated to
this one — they're two separate extensions as far as Chrome is concerned,
by design, since this is a fresh rebuild under a new name.

## If you ever need to regenerate this key
Don't, unless `extension-signing-key.pem` is compromised — regenerating
produces a different ID, which Chrome treats as a brand new extension, and
every existing install would need reinstalling.
