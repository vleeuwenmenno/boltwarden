# 1.0.0-rc.1 testing checklist

This checklist records manual verification of the exact tagged release artifacts.
Unchecked items are unverified, not passed. Automated CI covers both CPU builds,
Rust and extension tests, synthetic Chromium/Firefox flows, Debian install/startup/
removal, dependency audits, packaging, and checksum validation.

## Maintainer-reported testing

On 2026-10-02, the maintainer confirmed successful login/2FA, offline unlock,
browser filling, and pairing revocation against a real Vaultwarden account on
the pre-RC build. This does not claim independent verification, Bitwarden coverage,
or validation of the subsequently generated tagged artifacts.

## Desktop and packaging

- [ ] Install, upgrade, and remove on a clean Debian/Ubuntu desktop (x86_64).
- [ ] Install, upgrade, and remove on a clean Debian/Ubuntu desktop (ARM64).
- [ ] Install, upgrade, and remove on Arch and Arch Linux ARM.
- [ ] Accept and decline user-service setup; verify login startup after opting in.
- [ ] Launch quick access and the vault window on Wayland and X11.
- [ ] Resize both dividers, restart, and confirm widths and version display.

## Disposable real account

Repeat with Vaultwarden and Bitwarden where available. Record the server version,
distro, architecture, browser version, and exact release asset used. Never include
passwords, card numbers, recovery codes, tokens, or private keys in test reports.

- [ ] Login, two-factor authentication, logout, and account switching.
- [ ] Lock, automatic lock, offline unlock, reconnect, and sync.
- [ ] Create/edit/delete a disposable item and verify it in the server web vault.
- [ ] Pair Chrome/Chromium and Firefox; compare fingerprints and browser labels.
- [ ] Fill login/TOTP/test-card fields and save/update a disposable login.
- [ ] Protected-item approval and cancellation; navigate or lock during a fill.
- [ ] Create/use a disposable passkey; confirm rejection/cancellation behavior.
- [ ] Revoke each pairing; confirm the extension cannot access the vault afterward.
- [ ] SSH signing approval, denial, and lock behavior with a disposable SSH key.

## Distribution still pending

- [ ] Chrome store account/listing and final native-host extension identity.
- [ ] Firefox signing and a persistent signed-XPI installation test.
- [ ] Hosted privacy URL, extension screenshots, and listing review.
- [ ] Nix builds validated separately before claiming tested Nix support.

A public testing RC may document these limitations. Do not describe unsigned ZIPs
as store-ready installations, or mark final 1.0 stable until relevant checks pass.
