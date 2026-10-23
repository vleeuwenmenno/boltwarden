# Boltwarden 1.0.0-rc.5

A testing release candidate, not the final stable 1.0 release.

## Browser pairing

- Align native messaging with the published Chrome Web Store extension identity.
  This fixes pairing for the store extension in Brave Origin and other supported
  Chromium browsers.
- Migrate existing registrations that exactly match Boltwarden's retired
  development identity. Custom registrations and broader allowlists are left
  untouched. If the browser is not registered, enable it in Settings → Browser
  setup, then retry pairing.

## Vault and clipboard

- View stored password history on login items in quick access and the vault
  window. Entries are concealed by default and retain the item's master-password
  verification requirement.
- Choose when copied desktop secrets are cleared: 10 seconds to 5 minutes, or
  Never. Existing settings retain the 45-second default; locking still clears
  the clipboard.
- Local development builds show a git-derived version so they can be distinguished
  from tagged releases.

## Maintenance

- Update dependencies for the reported ctutils advisory and yanked clipboard-win
  version. Security checks remain enabled.

## Downloads and validation

Linux x86_64 and ARM64 tarballs, Debian, Arch and RPM packages; Windows x64
installer and ZIP; and a universal macOS app ZIP are provided with SHA-256
checksums. Linux requires glibc 2.36+ and the packaged desktop dependencies.
RPM downloads are unsigned and do not create an update repository.

Windows artifacts remain unsigned previews. The macOS app is signed ad hoc,
not with a Developer ID. Passkeys remain experimental. Automated fixtures and
packaging tests do not replace real-account and desktop-session checks; use a
disposable account for candidate testing.

Browser extension 0.5.10 is released separately and fixes missing verification-code
previews in automatically opened suggestions. GitHub browser ZIPs are developer
artifacts, not browser-store submissions or a signed Firefox XPI.

[Changes since RC4](https://github.com/vleeuwenmenno/boltwarden/compare/v1.0.0-rc.4...v1.0.0-rc.5)
