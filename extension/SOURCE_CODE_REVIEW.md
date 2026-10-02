# Building Boltwarden

Use Node.js 22.12 or newer and npm. From this directory, run:

```sh
npm ci
npm run typecheck
npm test
npm run build
```

The Firefox Manifest V3 extension is generated in `.output/firefox-mv3`.
The Chromium Manifest V3 extension is generated in `.output/chrome-mv3`.
All dependencies are locked in `package-lock.json`. WXT generates the manifest
and bundles the locally included TypeScript and Preact sources. The extension
does not download executable code or include a vault. Its native messaging host,
`nl.mvl.boltwarden`, must be installed separately by the Boltwarden desktop app.

`npm run zip` packages both extensions and the Firefox source archive. Packaging
omits the development `key` from the Chrome Web Store ZIP and restores it in the
unpacked build. `npm run check:release` also requires Python 3 to inspect the ZIP.
The Chrome manifest key is public and identifies the unpacked development build;
it is not a signing key or a native connection credential.

Inline login suggestions are bundled in the isolated content script and styled
inside a closed shadow root. They do not inject styles into the page or use page
message handlers for privileged actions. Trusted gestures request matching through
the document's existing extension port; document identity, generation, pinned form,
active tab, and offered item IDs are checked before filling. Cross-origin and HTTP
confirmation remains in the toolbar. `npm run test:inline` checks real inline
filling in disposable Chromium and Firefox profiles with synthetic credentials.

`npm run test:passkeys` builds both targets and exercises real WebAuthn calls in
disposable Chromium and Firefox profiles. It also requires `chromium`, `firefox`,
and `openssl`; `CHROMIUM_BIN` and `FIREFOX_BIN` can override browser paths. Firefox
uses its built-in Marionette protocol. The localhost HTTPS server and native host
use synthetic credentials only; they never access a personal profile or vault.
The synthetic host lives under `tests/` and is not included in extension bundles.

`public/bolt.svg` is the canonical split-shield mark, also embedded by the desktop
app. The committed PNGs need no generation step for normal builds. To regenerate
them, install librsvg (`rsvg-convert`, generated with version 2.62.3), then run:

```sh
node scripts/generate-icons.mjs
node scripts/generate-icons.mjs --check
```

This script uses only Node built-ins and the SVG included in the source archive;
it does not require the Rust project. Different librsvg versions may rasterize
edge pixels differently. Chromium uses a neutral gray mark; Firefox additionally
uses light and dark toolbar variants according to the toolbar text color, as
documented in [Firefox action.theme_icons](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/action#theme_icons).

## Release disclosures

Firefox 140+ provides built-in consent for the declared native messaging data
categories. See `public/privacy.html` and `public/LICENSE` for the packaged privacy
notice and MIT with Commons Clause license. Pending-save credentials live in
browser session storage, not persistent local storage; they remain until saved,
discarded, or the browser session ends.
