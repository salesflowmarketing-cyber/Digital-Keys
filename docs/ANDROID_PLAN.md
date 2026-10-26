# Digital Keys on Android

Status: **plan only — nothing built yet.** This document exists so the Android
client is designed against the same vault format and broker protocol as the
Linux one, instead of being retrofitted later.

## The hard constraint, stated honestly

On Android, when Digital Keys fills a credential into an app or a browser field,
**that app sees the plaintext.** The Autofill framework requires it: the
system hands the selected value to the target app.

So the guarantee is *not* "no app ever sees your key". It is:

- No **agent** (goose / opencode / an LLM) ever sees the key.
- No **cloud broker** ever sees the key — there is no server, it is local.
- The number of apps that see it is limited to ones you explicitly approved
  for that specific record, one use at a time.

That is still a real improvement over pasting keys into agent configs, but
README and marketing must never claim otherwise. KeyPass and every other
Android password manager are in the same position; it is a platform limit,
not a Digital Keys bug.

## Why Android is third, not first

The user agreed to the order Fedora → Windows → Android. That is right for
these reasons:

1. Autofill is the *only* useful credential-release mechanism on Android, and
   it requires a real APK, a manifest, a system settings toggle and a device
   to test on.
2. The per-use approval model needs an approval Activity reachable from a
   `PendingIntent`. That is Android-specific and untestable on a desktop.
3. A botched Autofill service can wedge the system credential picker, which is
   hard to recover from without uninstalling.
4. The vault format and broker protocol — the actually novel parts — are
   already platform-neutral Python and are being validated on Fedora first.

## Architecture: reuse, don't rewrite

The vault file format is identical to Linux. An Android app does **not** need
to reimplement Argon2id or the broker.

```
/data/data/app.highlinevault/files/vault.json      <- same format as Fedora
        |
        v
Termux / python3  <-- runs the SAME Digital Keys code
        |
        v
broker on 127.0.0.1:8787  (loopback only, as on Linux)
```

This is the highest-leverage decision for the Android version: **the Android
app shells out to the same Python broker** rather than porting the crypto to
Kotlin. One codebase, one set of test vectors, one set of bugs.

The Kotlin app is then only responsible for:

- Encrypted export/import of `vault.json` (so a phone can be a *second* vault,
  not the source of truth)
- Per-use approval Activity for Autofill
- An optional local OpenAI-compatible base-URL entry so goose/opencode on the
  phone can point at the broker

## The Autofill flow, concretely

1. App registers `<service android:name=".VaultAutofillService"
   android:permission="android.permission.BIND_AUTOFILL_SERVICE">`
2. User enables it in Settings → Passwords & accounts → Autofill service
3. A target app shows a login form; the system calls `onFillRequest`
4. Service returns a `FillResponse` whose entries are *labels only* —
   "OpenRouter", "GitHub", "My Bank" — with **no secret in them**
5. User taps one; the system fires our `IntentSender`
6. `ApproveActivity` launches, and must show:
   - which app is asking (package name, resolved and displayed)
   - which record
   - which provider base URL the key will be sent to
   - a biometric / device-credential prompt
7. On success, `ApproveActivity` returns an authenticated `Dataset` built
   with `setValue(..., null, presentation)` for the approved field only
8. Vault reseals immediately. The next fill needs a new approval.

Step 6 is the whole product. Skipping it is how 5- and 30-minute approval
windows happen.

## Per-credential app allowlist (a real requirement, not optional)

Approving "GitHub" once must not mean a phishing clone of GitHub gets it next
time. Store, per record, the set of package names and web origins the user
approved. On a request for a different origin, require a fresh approval and
offer to add it.

This is a genuine improvement over desktop-first tools, and it is *required*
before any real key goes in.

## Package layout if/when we build it

```
Digital Keys-android/
  app/src/main/java/app/highlinevault/
    AutofillService.kt      - onFillRequest / onSaveRequest
    ApproveActivity.kt      - biometric gate, returns authenticated Dataset
    VaultBridge.kt          - talks to the Python broker over 127.0.0.1
    ExportImport.kt         - encrypted vault.json transfer
  app/src/main/res/xml/autofill_service.xml
  app/src/main/AndroidManifest.xml
  app/src/test/             - cross-check vault vectors against the Python impl
```

## Build order when we get there

1. Lock the vault format and add cross-language test vectors (Python writes,
   Kotlin reads, and vice versa)
2. Trivial APK that imports/exports an encrypted `vault.json`
3. Autofill service returning *labels only*, no approval yet — to prove the
   wiring
4. `ApproveActivity` with biometric + fresh auth per use
5. Per-credential app/origin allowlist
6. Local OpenAI-compatible route for mobile goose/opencode
7. `onSaveRequest` (save a new credential after the user types one)

Do not skip to step 4. Steps 1–3 are the ones that are annoying to retrofit.

## Explicitly not doing on Android

- No cloud sync of a decrypted vault. Ever.
- No long-lived unlock session. Every fill re-authenticates.
- No background service holding an unlocked vault between fills.
- No `INTERNET` permission for autofill reasons; the broker is loopback. If
  the app ends up with INTERNET for the agent integration, it must be
  declared and justified in the manifest, not slipped in.
