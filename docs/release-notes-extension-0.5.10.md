# Boltwarden browser extension 0.5.10

- Show the first eligible verification-code preview and countdown when an inline
  suggestions menu opens automatically. Previewing does not select or fill an
  item: Enter still passes through until you explicitly select a suggestion.
- Preserve protected-item checks and avoid showing a different item's code when
  the first suggestion requires verification.
- Align unpacked development builds with the published Chrome Web Store identity.
  Use desktop 1.0.0-rc.5 for corrected native-host registration and migration.
- Refresh extension test dependencies.

Chrome and Firefox ZIPs and reviewer source are included with SHA-256 checksums.
GitHub assets do not update browser stores. The Firefox ZIP is unsigned; a signed
XPI requires Mozilla submission. Passkeys remain experimental.

[Changes since 0.5.9](https://github.com/vleeuwenmenno/boltwarden/compare/extension-v0.5.9...extension-v0.5.10)
