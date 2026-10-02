# Boltwarden browser extension

The extension fills usernames, email addresses, and passwords and handles supported passkey
requests through a running Boltwarden desktop daemon. It persistently stores its pairing ID and a non-extractable pairing key. Pending
password saves use browser session storage until saved, discarded, or the session
ends; locking does not discard them. Matching,
vault locking, and master-password verification remain in the desktop app.

## Development

Use Node.js 22.12 or newer:

```sh
npm ci
npm run typecheck
npm test
npm run build
```

Load `.output/chrome-mv3` as an unpacked Chromium extension. Firefox temporary
development installs use `.output/firefox-mv3/manifest.json` through
`about:debugging`. Firefox release installs require Mozilla signing. Native
messaging can be configured in desktop **Settings → Browser setup**, which detects
installed browsers and supports custom executable/native-host paths. The CLI
`boltwarden install-browser --browser all` is also available, including Vivaldi,
Brave, and Edge. Enable browser integration in desktop settings, open the extension,
and select **Pair with Boltwarden**. Compare the fingerprint with the desktop approval prompt.

`npm run dev` starts WXT's Chromium development mode. `npm run dev:firefox` starts
Firefox development mode. Do not use a personal vault for automated fixtures.

## Filling

Focus a username, email, or password field and click its Boltwarden mark, or press
Arrow Down, to show matching logins. Arrow keys select, Enter fills, Escape closes,
and Tab preserves the page's normal focus order. Dynamic forms and open shadow
roots are supported. HTTP pages and cross-origin frames hand off to the toolbar
for confirmation. Protected items still use desktop master-password verification.

The inline UI is isolated in a closed shadow root and accepts only trusted user
gestures. It never reads typed passwords. Suggestions contain names and usernames;
credentials travel only to the exact document and form selected for filling.
Moving focus, navigating, locking, and disconnecting cancel stale operations.

Press **Ctrl+Shift+L** over a login form. One eligible match fills directly;
multiple matches open the picker where the browser allows it. If the popup cannot
open, its toolbar badge indicates that a click is required. Firefox 140–148 can
require that click after an asynchronous native lookup. Master-password reprompt
items require explicit selection and desktop verification; HTTPS-to-HTTP downgrades
and cross-origin frames require toolbar confirmation.

The extension never submits forms. Ambiguous forms require selecting a login
field and trying again. Password-change and registration fields are excluded.
Open shadow roots are supported; closed shadow roots and non-HTTP(S) documents
are not. Reload pages that were already open when the extension was installed.

The popup uses the same split-shield mark and compact row layout as desktop quick
access. It lists logins matching a supported, visible login form on the current
page. **Filter this page’s logins** narrows the loaded matches by name or username;
use desktop quick access to search the whole vault. Use the arrow keys and Enter
to select and fill. Further matches remain available
through **Load more matching logins**. The popup follows vault lock/unlock and page changes live.
Risk confirmations initially focus **Deny** and require an explicit choice to fill.

## Passkeys

Use the site's normal passkey button. The desktop prompts for account selection
when needed and explicit approval. Desktop **Settings → Passkey verification**
offers **Always ask** (the default), **Only when required**, and **Use vault unlock**.
The last option reuses verification from the current authenticated vault session:
choose an account and approve without retyping the password, including on sites
that require verification. Item-level reprompt still requires a fresh password.
Locking the vault, changing accounts, or restarting ends verification reuse.
Choose **Other device** for the browser's native authenticator flow. Creation
saves a new personal login before returning success; it requires a server
connection. The extension never receives private keys.

The first profile supports top-level HTTPS, ES256/P-256, zero signature counters,
discoverable credentials, `none` attestation, and `credProps`. Unsupported contexts
or options delegate to native WebAuthn. Iframes, conditional mediation, PRF,
large blobs, nonzero counters, and browser-internal credential slots are outside
this profile. WebAuthn static capability checks retain native browser behavior.
Requests made before the page finishes loading may fall back to native WebAuthn.
Reload pages after updating the extension. Read the main README for storage,
verification, and interoperability limits.

## Tests

`npm test` checks protocol fixtures, pairing signatures, native-port lifecycle,
form classification, and background routing/cancellation. DOM layout checks use
real browser tests rather than treating happy-dom as a layout engine.

```sh
npm run test:e2e
```

The end-to-end test requires a `chromium` executable (`CHROMIUM_BIN` overrides
its path) and permission to bind a loopback fixture server. It creates a temporary
HOME and browser profile, installs a test-only native host there, and removes both
afterwards. The host verifies real P-256 pairing proofs and serves synthetic login
credentials. Tests cover pairing, popup fill, selection between multiple accounts,
live lock/unlock updates, search and keyboard selection, explicit risk confirmation,
and rejecting delayed credentials after same-origin document replacement. No
personal browser profile or vault is used. This password-filling harness runs
Chromium only.

Inline filling has its own Chromium and Firefox tests:

```sh
npm run test:inline
```

These require `chromium`, `firefox`, and `openssl` and use disposable profiles with
synthetic credentials. They cover trusted keyboard/icon interaction, email fields,
dynamic forms, open shadow roots, synthetic-event rejection, and cancellation after
field or frame focus changes. Chromium also tests HTTP handoff and a vault refresh
during a pending fill. `CHROMIUM_BIN` and `FIREFOX_BIN` can override browser paths.
`BOLTWARDEN_TEST_HEADFUL=1` runs the Chromium harness on the current X11 display.

The passkey harnesses run real extension builds in both Chromium and Firefox:

```sh
npm run test:passkeys
```

They require `chromium`, `firefox`, and `openssl` (`CHROMIUM_BIN` and `FIREFOX_BIN`
can override browser paths). Each uses a disposable profile, a localhost HTTPS
fixture, and a synthetic native host. They exercise real WebAuthn page calls and
verify registration/assertion data independently with Node/OpenSSL. Firefox uses
its built-in Marionette protocol; no geckodriver or personal profile is needed.

Set `BOLTWARDEN_TEST_SCREENSHOTS=/absolute/output/directory` to save screenshots of
the synthetic pairing, matching, locked, filtered, and confirmation screens.

`npm run zip` generates both browser archives and the Firefox source archive.
Build instructions for source reviewers are in `SOURCE_CODE_REVIEW.md`.

## Publishing and privacy

Release builds require Firefox 140+ or Chromium 127+. See
[PUBLISHING.md](PUBLISHING.md) for store metadata, identities, permissions, and
submission steps, and [the privacy notice](../PRIVACY.md) for data handling.
The extension uses [MIT with Commons Clause v1.0](public/LICENSE).

## Credit card autofill

Focus a payment field on an HTTPS checkout, open the Boltwarden toolbar popup,
and select a saved card. The list shows the card name, brand, and last four digits.
The shortcut opens the picker rather than silently choosing a card. Protected cards
still require a fresh master-password check in the desktop app. Embedded payment
frames require destination confirmation and are filled separately.

Supported fields use standard `autocomplete` purposes: `cc-name`, `cc-given-name`,
`cc-family-name`, `cc-number`, `cc-csc`, `cc-exp`, `cc-exp-month`, `cc-exp-year`, and
`cc-type`. Inputs, expiry dropdowns, and open shadow roots are supported. Generic
unmarked fields, duplicate ambiguous fields, hidden/disabled fields, and closed
shadow roots are not filled. Card fills never submit a form or save card details
in extension storage. Cards are offered independently of login URL matching.
