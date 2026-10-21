# Boltwarden browser extension 0.5.9

## Passkeys and reliability

- When Boltwarden cannot be reached, choose **Try again**, **Use browser instead**
  or **Cancel** rather than silently falling back or waiting for the full page
  deadline. Extension settings remember whether to ask, use the browser, or cancel.
- Detect a stale extension background after an update and replace stuck passkey
  requests. Retried requests remain bound to the current document and deadline.
- Improve Firefox integration-test readiness checks.

## Dependencies and desktop integration

- Update Preact, Vitest and happy-dom. Patch Vite's editor-launch security
  advisories and its compatible build dependencies.
- With desktop 1.0.0-rc.4, matching login, card and TOTP suggestions come directly
  from desktop memory while due server refreshes run in the background. Secrets
  remain controlled by desktop authorization and are sent only when needed for
  the selected operation.

## Download status

The Chrome ZIP, Firefox ZIP and Firefox reviewer source ZIP each include a
SHA-256 checksum. The extension requires the separate Boltwarden desktop app.
Passkeys remain experimental.

These are GitHub developer artifacts. Chrome Web Store submission is separate;
the Firefox ZIP is unsigned and is not a normal persistent-install XPI. AMO signing
and testing the signed XPI remain separate steps. Validate pairing, fills,
passkeys and revocation with a disposable account before using this candidate
with important credentials.

[Changes since 0.5.8](https://github.com/vleeuwenmenno/boltwarden/compare/extension-v0.5.8...extension-v0.5.9)
