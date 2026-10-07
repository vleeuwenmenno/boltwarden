# macOS

The macOS build is **unsigned** and runs on macOS 11 or later, as one universal app
for Apple silicon and Intel Macs. It is signed ad hoc rather than with an Apple
Developer ID, so macOS asks you to approve it once. Evaluate it with a test vault.
Turn on **Start at login** in **Settings → General** to start Boltwarden in the menu
bar when you log in.

## Download and installation

Releases include `boltwarden-VERSION-universal-macos.zip` with a `.sha256` checksum.
It contains `Boltwarden.app`.

1. Open the ZIP and move **Boltwarden.app** to **Applications**.
2. Open Boltwarden. macOS reports that it cannot verify the developer.
3. Open **System Settings → Privacy & Security**, scroll to Security, and choose
   **Open Anyway** next to the Boltwarden message. Confirm with your password.

macOS remembers the approval, until you replace the app with a newer download.
Alternatively, clear the download quarantine from Terminal before the first launch:

```bash
xattr -dr com.apple.quarantine /Applications/Boltwarden.app
```

Boltwarden runs in the menu bar, without a Dock icon. Its menu opens quick access,
opens the vault window, and quits. The vault window shows a Dock icon while it is open.

## Quick access shortcut

Open **Settings → General**, select **Quick access shortcut**, and press Return to
record. Hold Control, Option, Shift, or Command and press a letter, digit, Space, or
F1–F20; the shortcut applies at once. Escape cancels recording and Backspace clears
the shortcut. No permission prompt is needed, and the shortcut works while the vault
is locked. A combination another app already uses shows an error and keeps the
previous shortcut. Keys are matched by their position on a US keyboard layout.

Quick access opens over full-screen apps on the current Space.

## Browser integration

Open **Settings → Browser integration**, enable it, and choose **Browser setup**.
Boltwarden finds these browsers in `/Applications` and `~/Applications`:

| Browsers | Native-host folder in `~/Library/Application Support` |
| --- | --- |
| Firefox, Firefox Developer Edition | `Mozilla/NativeMessagingHosts` |
| LibreWolf | `LibreWolf/NativeMessagingHosts` |
| Google Chrome, Beta, Dev | `Google/Chrome…/NativeMessagingHosts` |
| Chromium | `Chromium/NativeMessagingHosts` |
| Microsoft Edge, Beta, Dev | `Microsoft Edge…/NativeMessagingHosts` |
| Brave, Beta, Nightly | `BraveSoftware/Brave-Browser…/NativeMessagingHosts` |
| Vivaldi | `Vivaldi/NativeMessagingHosts` |

Select browsers and apply, then install the extension and pair each browser profile.
For other browsers, such as Arc, Opera, or Zen, choose **Add browser** and enter the
executable inside the app (for example
`/Applications/Arc.app/Contents/MacOS/Arc`) and the browser's native-host folder.

Registration writes a manifest per browser and a launcher at
`~/.local/libexec/boltwarden-native-host`. The launcher points at the app; after moving
Boltwarden.app, start it once and it updates the launcher. From Terminal:

```bash
/Applications/Boltwarden.app/Contents/MacOS/boltwarden install-browser --detected
/Applications/Boltwarden.app/Contents/MacOS/boltwarden uninstall-browser --browser all
```

## Security behavior

- Copied values stay on this Mac (no Universal Clipboard), carry the
  `org.nspasteboard.ConcealedType` marker that clipboard managers skip, and are
  cleared after 45 seconds unless something else was copied since.
- The vault locks when the screen locks, after the configured idle time, and when the
  Mac sleeps. Disable these in **Settings → General**.
- The SSH agent identifies requesting processes with macOS process information and
  asks for approval in the desktop app before signing.

## Files

| Purpose | Location |
| --- | --- |
| Settings and encrypted session data | `~/.config/boltwarden` |
| Icon cache | `~/.cache/boltwarden` |
| Daemon sockets | `~/Library/Application Support/boltwarden` |

Uninstalling the app keeps these folders. Remove them as well for a clean uninstall.

## Commands

The executable inside the app accepts the same commands as on Linux:

```bash
/Applications/Boltwarden.app/Contents/MacOS/boltwarden toggle
/Applications/Boltwarden.app/Contents/MacOS/boltwarden window
/Applications/Boltwarden.app/Contents/MacOS/boltwarden quit
```

## Building

Install Xcode or its command line tools and Rust, with both macOS targets:

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
make package-macos
```

This writes the universal ZIP and checksum to `dist/`, the same artifact CI builds and
smoke-tests (`python3 scripts/macos-smoke.py dist`) for every desktop change and
release.
