# Boltwarden 1.0.0-rc.1 / browser extension 0.5.6

First 1.0 release candidate for testing, not the final stable 1.0 release.

## Downloads and testing status

- Desktop: Linux x86_64 and ARM64 tarballs, Debian packages, and Arch packages.
  Requires glibc 2.36+ and the listed desktop libraries.
- Browser: separate Chrome and Firefox ZIPs, plus the Firefox reviewer source ZIP.
  These are unsigned developer artifacts; no store listings are published yet.
  Firefox ZIPs support temporary development loading, not normal persistent installation.
- API: browser integration protocol v1. Extension version remains 0.5.6 independently
  of the desktop RC version.
- Package versions: Debian `1.0.0~rc.1`, Arch `1.0.0rc1-1`; both upgrade to final 1.0.0.
- Passkeys remain experimental. Firefox can fall back to its own authenticator when
  navigation timing cannot securely identify the current document. The maintainer reports successful Vaultwarden login/2FA,
  offline unlock, filling, and revocation on the pre-RC build. Exact tagged artifacts,
  Bitwarden, and the remaining desktop/session checks still need manual validation.

See [the RC testing checklist](https://github.com/vleeuwenmenno/boltwarden/blob/v1.0.0-rc.1/docs/rc-testing.md).
Back up important vault data and use a disposable account for first-pass testing.
Do not use this release candidate as your only route to important credentials.

## Security and privacy

- Bound untrusted password-derivation parameters to prevent excessive CPU/memory use.
- Require HTTPS for website icons, including redirects, and exclude `.onion` and
  `.i2p` hostnames from icon-service requests.
- Replace a yanked Rust dependency and enable advisory checks in CI.
- Correct Firefox data-transmission disclosures for native messaging. Firefox 140+
  is now required so installation uses built-in data consent.
- Document pending-save credentials held in browser session storage. Locking does
  not discard these credentials; use the extension's Discard action when needed.

## Desktop settings and acknowledgements

The full vault window now groups settings into General, Browser integration, and
SSH integration tabs, with the same preferences as quick access. Both provide
licenses and acknowledgements, including searchable dependency and font license
texts embedded in release binaries for offline viewing. Toolbar buttons now show
hover and pressed feedback. Closing the full window gracefully shuts down its
clipboard worker, fixing a Wayland shutdown crash.

Sidebar and item/detail divider widths are saved across restarts. Desktop and
browser API versions are visible in Settings and through the `version` / `about`
quick commands or `boltwarden --version`; extension settings show their own
installed version and browser API version. Paired browser extensions now provide
a Back to Settings action and descriptive browser names for new pairings, while
preserving key fingerprints as their identity.

## Credit card autofill

Select a saved credit card in the toolbar popup on an HTTPS payment form. Listings
show only names, brands, and last four digits. Detection supports standard `cc-*`
fields and clearly labeled payment forms without autocomplete attributes. An
inline card button opens the toolbar picker for explicit selection. Protected cards require a fresh password,
embedded frames require destination confirmation, and navigation or locking cancels
pending fills. Payment forms are never submitted automatically. Firefox data consent
and privacy disclosures now include financial/payment information.

## Browser compatibility

- Fix inline suggestions on Firefox ESR when constructed stylesheets are rejected
  through content-script Xray wrappers. Styles remain in the closed shadow root.
- Make browser fixtures wait for actual pairing readiness and native cancellation.
- Use the browser's epoch navigation-to-parser-start interval for passkey document
  binding, avoiding Firefox fallback from rounded clocks and fast first-byte timing.
  Exact interval checks and one-document response ownership remain enforced.
- Bundle privacy, project-license, and third-party-license notices in store archives.

## Distribution and setup

- Add GitHub Actions checks and native x86_64/ARM64 release jobs.
- Build Linux tarballs, Debian packages, and Arch/Arch Linux ARM packages with
  checksums. Binaries require glibc 2.36+ and the listed desktop libraries.
- Include an optional systemd user service. Run `boltwarden-setup` as your desktop
  user to choose graphical-login autostart. Package installation does not enable it.
- Tags create draft releases only after checks pass; published assets are not overwritten.
- `make` now shows colored, grouped help. Build with `make release`.

## License

Boltwarden is now explicitly source-available under MIT with Commons Clause v1.0.
Internal business use is permitted. Sales of products/services whose value derives
entirely or substantially from Boltwarden are restricted; distributions retain
Menno van Leeuwen's copyright and the full license. Dependencies keep their own licenses.

See [release preparation](https://github.com/vleeuwenmenno/boltwarden/blob/v1.0.0-rc.1/docs/releasing.md) for installation checks, store submission,
and remaining maintainer configuration. Browser store submission and signing remain separate from this testing release.
