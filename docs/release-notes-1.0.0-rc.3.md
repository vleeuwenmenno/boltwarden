# Boltwarden 1.0.0-rc.3 / browser extension 0.5.7

Third 1.0 release candidate for testing, not the final stable 1.0 release.
`v1.0.0-rc.2` was tagged before its version bump and failed the release check, so
it has no release; this candidate follows 1.0.0-rc.1.

## Downloads and testing status

- Desktop: Linux x86_64 and ARM64 tarballs, Debian packages, Arch packages, and new
  Fedora RPMs. Requires glibc 2.36+ and the listed desktop libraries.
- Windows: new unsigned Windows 11 x64 preview installer and ZIP. See
  [Windows setup](https://github.com/vleeuwenmenno/boltwarden/blob/v1.0.0-rc.3/docs/windows.md).
- Browser: separate Chrome and Firefox ZIPs, plus the Firefox reviewer source ZIP.
  Extension version is 0.5.7, numbered independently of the desktop version.
- Package versions: Debian and RPM `1.0.0~rc.3`, Arch `1.0.0rc3-1`; all upgrade to
  final 1.0.0.
- Passkeys remain experimental.

Back up important vault data and use a disposable account for first-pass testing.
Do not use this release candidate as your only route to important credentials.

## Faster quick access and vault window

Quick access and the vault window now show items from the unlocked in-memory
vault immediately instead of waiting for a server sync. Each window starts a
background sync when it opens, and the server round trip no longer blocks
searching or copying. A sync that overlaps a lock, unlock, token refresh, or edit
is discarded rather than applied over newer data.

## Website links and copying

- Website fields show an open-in-browser action. Click it or press Enter to open
  the address in the default browser; quick access hides afterwards. Only http(s)
  addresses and bare domains open. App links and other schemes keep the copy action.
- Ctrl+C copies the selected field of any kind, including websites.
- Footer hints combine the arrow keys into a single Navigate entry.

## Windows preview and shortcuts

- New unsigned Windows 11 x64 preview with a per-user installer and ZIP, Chrome,
  Edge, and Firefox native-messaging registration, and optional start at sign-in.
- Configure the quick access shortcut in **Settings → General → Quick access
  shortcut**. Windows registers it while Boltwarden runs; on Hyprland, Boltwarden
  manages an included bindings file and restores the configuration if validation fails.
- Drag the logo or empty header space to move quick access.

## Packaging and browser stores

- Add Fedora RPM packages for both CPUs, with clean-container install checks.
- Keep `~` out of release download filenames and verify uploaded assets after release.
- Prepare Chrome Web Store and Firefox packages and listing assets.

See [release preparation](https://github.com/vleeuwenmenno/boltwarden/blob/v1.0.0-rc.3/docs/releasing.md)
for installation checks. Browser store submission and signing remain separate from
this testing release.
