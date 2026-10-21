# Boltwarden 1.0.0-rc.4

A testing release candidate, not the final stable 1.0 release.

## Vault and browser performance

- Browser login, card and TOTP suggestions return matching summaries from the
  unlocked desktop vault in memory. Due server refreshes run in the background
  without holding the vault lock, and the extension receives refreshed matches
  or warnings. Item verification, destination checks and confirmed-revocation
  handling remain enforced.
- Offline unlock also works when a reachable server refuses the request, including
  reverse-proxy/IP-allowlist 403 responses, rate limiting and server outages. The
  offline tooltip explains the failure. Confirmed session revocation still clears
  the session and prevents offline fallback.

## Editing and health

- Duplicate a supported item from the full-window context menu, change its fields,
  and save a new item. Passkeys and linked fields are excluded; SSH keys cannot be
  duplicated through the editor.
- Create and edit cards and identities alongside logins and secure notes.
- Generate passwords or passphrases in the editor with remembered options.
  Generated passwords are visible while choosing them and are stored only when
  the item is saved.
- Vault health identifies breached websites and personal-data breaches, and adds
  an opt-in Pwned Passwords check for exposed passwords.

## Installation and security

- Linux Start at login uses an XDG autostart entry controlled by the app setting.
- On macOS, `make install` installs the packaged universal app ZIP, checks its
  signature and available checksum, and restarts a running app after replacement.
  `make uninstall` removes the app bundle. `APP_DEST` and `MACOS_ARCHIVE` override
  the destination and archive.
- Patch rustls, rustls-webpki and webpki-roots for the reported TLS and certificate
  advisories. Refresh compatible Rust dependencies and build tooling.
- Three specific maintenance notices for crates merged into zbus 6 are temporarily
  excepted while tray/accessibility dependencies migrate. Vulnerability checks
  remain enabled; removal is tracked in
  [#75](https://github.com/vleeuwenmenno/boltwarden/issues/75).

## Downloads and validation

This release contains Linux x86_64 and ARM64 tarballs, Debian, Arch and RPM
packages; a Windows x64 installer and ZIP; and a universal macOS app ZIP, each
with a SHA-256 checksum. Linux requires glibc 2.36+ and the packaged desktop
dependencies. RPM downloads are unsigned and do not create an update repository.

Windows artifacts remain unsigned previews. The macOS app is signed ad hoc rather
than with a Developer ID. Passkeys remain experimental. Automated synthetic and
packaging tests do not replace real-account and desktop-session checks; use a
disposable account for candidate testing. Validation is tracked in
[#78](https://github.com/vleeuwenmenno/boltwarden/issues/78).

Browser extension 0.5.9 is released separately. GitHub browser ZIPs are developer
artifacts, not browser-store submissions or a signed Firefox XPI.

[Changes since RC3](https://github.com/vleeuwenmenno/boltwarden/compare/v1.0.0-rc.3...v1.0.0-rc.4)
