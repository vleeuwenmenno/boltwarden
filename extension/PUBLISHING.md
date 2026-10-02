# Publishing Boltwarden

## Listing draft

**Name:** Boltwarden

**Short description:** Fill logins and credit cards, and use passkeys with your Boltwarden desktop vault.

**Full description:**

Boltwarden connects your browser to the Boltwarden Linux desktop password manager.
Use inline suggestions, the toolbar popup, or Ctrl+Shift+L to fill matching logins.
Save new or changed passwords through desktop approval, fill supported verification
codes, select saved credit cards for standard payment fields, and use supported passkeys on HTTPS sites. Cards require HTTPS and explicit selection; the extension never submits a payment.

Install and run the separate Boltwarden desktop app, register your browser in
Settings → Browser setup, enable integration, and pair the extension by comparing
the fingerprint shown in the browser and desktop. A Bitwarden or Vaultwarden
account is required for real vault use. The extension does not provide an independent
vault and does not require the official Bitwarden browser extension.

Vault unlock, approvals, and protected-item master-password checks stay in the
desktop app. Pending password saves are retained temporarily for the browser session
until saved or discarded. This is an unofficial project, not affiliated with
Bitwarden or Vaultwarden. Currently Linux only; passkey support is experimental
and does not cover every WebAuthn option.

## Permissions and data disclosures

- `nativeMessaging`: exchanges pairing messages, page URLs, matching requests,
  saved login data, selected credentials, and passkey operations with the local app.
- `storage`: stores pairing metadata and pending-save credentials in session storage.
  Pairing keys are stored as non-extractable CryptoKeys in IndexedDB.
- `webNavigation`: binds requests to current documents and cancels navigation races.
- `webRequest`: checks HTTPS response Permissions-Policy for passkey eligibility;
  it is not used for advertising, tracking, or modifying traffic.
- HTTP/HTTPS host access: finds login fields and supports filling/saving across
  sites. HTTP or cross-origin filling needs confirmation; passkeys require HTTPS.

Firefox requires 140+ and declares `authenticationInfo`, `personallyIdentifyingInfo`,
`browsingActivity`, `financialAndPaymentInfo`, and `websiteContent`. Native messaging to a local program counts
as data transmission under Mozilla's rules; do not replace these with `none`.
See [Mozilla's native messaging consent guidance](https://extensionworkshop.com/documentation/develop/best-practices-for-collecting-user-data-consents/)
and [built-in consent](https://extensionworkshop.com/documentation/develop/firefox-builtin-data-consent/).

For Chrome, describe authentication information, identifying information (including
email usernames), financial/payment information, website URLs, and relevant page/form content consistently with
[PRIVACY.md](../PRIVACY.md). Do not claim the extension never processes or transmits
personal data simply because the app is local. It has no analytics, advertising,
data sale, or remote executable code. Complete the dashboard's data-use and permission
justifications using the exact behavior above, then review the current
[Chrome privacy fields](https://developer.chrome.com/docs/webstore/cws-dashboard-privacy).

## Build and inspect

```sh
# From the repository root:
make extension-deps extension-check extension-test extension-zip extension-release-check
# For release artifacts, use the Docker command in docs/releasing.md.
```

Artifacts are `.output/boltwarden-browser-VERSION-chrome.zip`, `-firefox.zip`, and
`-sources.zip`. Source archives contain the same reviewed sources and lockfile.
See [SOURCE_CODE_REVIEW.md](SOURCE_CODE_REVIEW.md) for reviewer reproduction and
synthetic browser fixtures. Do not upload development profiles or real vault data.
The generated store ZIPs contain LICENSE and a local privacy page. CI also bundles
third-party dependency license notices. Desktop and
extension versions are independent; bump package.json and its lockfile together
before each new store submission.

## Chrome Web Store

Create an unpublished listing and upload the Chrome ZIP. Retrieve its public key
from the developer dashboard and check that the assigned extension ID equals
`lib/browser-identities.json`'s `chrome_id`. The committed public key fixes the
unpacked development identity; it does not guarantee the store will assign that
identity. If different, replace `chrome_public_key` and `chrome_id` together,
rebuild both the desktop native host and extension, and retest pairing. Rust and
Nix read the same identity file; no wildcard native messaging allowlist is permitted.
See [Chrome's manifest key guidance](https://developer.chrome.com/docs/extensions/reference/manifest/key).

Use https://github.com/vleeuwenmenno/boltwarden as the homepage and
https://github.com/vleeuwenmenno/boltwarden/issues for support. Publish the privacy
notice at a publicly accessible URL and verify it loads without signing in. Supply icons, a 440×280 small
promotional tile, and screenshots showing the real extension with synthetic
credentials (1280×800 or 640×400; see [image requirements](https://developer.chrome.com/docs/webstore/images)). The committed 128×128 icon is available under
`public/icon/128.png`. Finish the single-purpose and data-use declarations before
submitting. Screenshots and promotional artwork must not imply official Bitwarden
affiliation. Store accounts, final ID, artwork, hosted URLs, and submission remain
maintainer actions; ZIP generation alone does not publish a listing.

## Firefox AMO

Use the existing `boltwarden@mvl.sh` add-on ID consistently. Upload the Firefox ZIP
for a listed extension, the corresponding source ZIP for code review, the listing,
privacy notice, license, and reviewer instructions. The custom license is **MIT
with Commons Clause v1.0**, not plain MIT. Explain that the separate Linux desktop
app is required and provide a downloadable tested desktop release and setup steps.
Do not provide personal credentials; offer synthetic fixtures and, if requested,
an isolated review account containing only synthetic data.

AMO signing produces the installable signed XPI. The generated Firefox ZIP is
unsigned and cannot be advertised as a normal release-installable add-on. Test
the actual signed XPI with the release desktop binary before announcing it.
Check Firefox install/update consent prompts and pair/revoke behavior in a clean
profile. See [Mozilla submission guidance](https://extensionworkshop.com/documentation/publish/submitting-an-add-on/).
