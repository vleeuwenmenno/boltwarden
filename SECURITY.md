# Security

Boltwarden handles passwords and passkeys. This repository's security checks and
regression tests are not an independent audit or a guarantee that vulnerabilities
are absent. Use a test vault when evaluating a new release.

## Reporting

Do not publish credentials, decrypted vaults, exploit details, or personal account
information in public issues. On GitHub, use **Security → Report a vulnerability**
when private vulnerability reporting has been enabled. If that option is absent,
contact [Menno van Leeuwen](https://github.com/vleeuwenmenno) to arrange a private channel
before sending details. Acknowledge the affected version, reproduction steps using
synthetic data, and impact. No response-time commitment is currently established.

## Trust boundaries

The desktop account, operating system, configured vault server, and paired browser
profile are trusted. Socket ownership and cryptographic pairing do not protect
against root or malware that can read or control that account. A compromised
paired extension can request credentials from an unlocked vault. A website receives
credentials intentionally filled into it, so locking cannot erase those values.

The daemon uses private Unix sockets, peer credentials, a separate desktop RPC
token, and browser pairing proofs bound to a nonce and native-host PID. Browser
requests are bounded, and lock/revoke/navigation races invalidate pending work.
Item reprompts and risky fills require explicit approval. Passkey origin and RP-ID
validation, user verification, and cancellation are enforced separately from the
page bridge. Persistent vault and refresh-session data are encrypted; pending
browser saves are session-only plaintext and require explicit discard if unwanted.

## Release review, 2026-10-02

The release preparation pass inspected account transport and KDF handling, private
storage, socket framing and authentication, browser pairing and document binding,
pending-save retention, icon downloads, extension permissions, and release workflows.

Fixed issues:

- Server/saved-session KDF parameters previously allowed excessive CPU or memory
  use. PBKDF2 is now bounded to 1–2,000,000 iterations; Argon2id to 1–10 iterations,
  1–1024 MiB and 1–16 lanes. Legacy low-cost configurations are still accepted;
  these checks bound resources and do not upgrade weak account settings.
- Icon downloads now enforce HTTPS, including redirected requests, and never
  send `.onion` or `.i2p` hostnames to the icon service.
- Firefox previously declared no data transmission despite native messaging.
  It now declares authentication information, identifying information, browsing
  activity, and website content, and requires Firefox 140+ for built-in consent.
- Privacy documentation now describes temporary credentials held for pending saves.
- Firefox document binding now uses the browser's epoch navigation-to-parser-start
  interval instead of independently rounded `timeOrigin` values and first-byte
  timing. Fast responses can precede the request event timestamp. No arbitrary
  timing tolerance is added, and a response still belongs to only one document.
- The yanked `yoke-derive` 0.8.3 dependency was updated to 0.8.4.
- Release shell scripts receive tag names through environment variables, and
  GitHub actions are pinned to commits. Only the final draft-release job can write
  repository contents; pull-request builds receive no publishing credentials.

Run `make security` to check current dependency advisories. The configured CI also
runs Rust tests and both browsers' integration fixtures before creating release
artifacts. See [release preparation](docs/releasing.md) for verification and manual
store/desktop checks still required before publishing.
