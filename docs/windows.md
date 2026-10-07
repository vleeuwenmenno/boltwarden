# Windows 11 x64 preview

The Windows build is an **unsigned preview**. Windows may display publisher or
reputation warnings. Evaluate it with a test vault. Supported preview browsers
are Chrome, Edge, and Firefox. Native ARM64, Windows 10 certification, SSH agent
transport, automatic updates, and store publication are not part of this release.
SSH items remain available for viewing and editing.

## Downloads and installation

Release CI produces `boltwarden-VERSION-x86_64-windows-setup.exe` and
`boltwarden-VERSION-x86_64-windows.zip`, each with a `.sha256` checksum. ZIP contents
are `boltwarden.exe`, `boltwarden-native-host.exe`, `LICENSE`,
`THIRD_PARTY_NOTICES.txt`, and `WINDOWS.txt`. Extract all files together.

The installer installs per user under `%LOCALAPPDATA%\Programs\Boltwarden` without
administrator access. Start-menu shortcuts are included. Desktop shortcut,
autostart at sign-in, and browser registration are separate unchecked options.
Autostart runs `boltwarden.exe --daemon`; there is no Windows service.

Both distributions keep encrypted session/vault data, pairing records, and
settings under `%LOCALAPPDATA%\Boltwarden`. The ZIP is an extract-and-run application,
not a portable vault. Uninstall preserves this data. Save edits and quit before
upgrading. Upgrades stop the existing daemon before replacing its executable.

## Browser setup

Keep `boltwarden-native-host.exe` beside the desktop executable. Open **Settings →
Browser integration**, select browsers, and apply. Install the separate extension
and pair each browser profile. Edge uses the existing Chromium extension build.
Registration writes HKCU native-messaging keys for Google Chrome, Microsoft Edge,
and Mozilla; no administrator or browser launch is required.

From PowerShell in the application directory:

```powershell
.\boltwarden.exe install-browser --browser all
.\boltwarden.exe uninstall-browser --browser all
.\boltwarden.exe --daemon
.\boltwarden.exe window
.\boltwarden.exe toggle
.\boltwarden.exe quit
```

Individual registration targets are `chrome`, `edge`, and `firefox`. Existing
foreign registrations are not overwritten or removed. Enterprise browser policies
can disable native messaging; registration does not bypass those policies.
Before moving a ZIP directory, unregister its browsers and quit. Register again
from its new location. Browser connections require an already running daemon.

Open **Settings → General**, select **Quick access shortcut**, and press Enter to
record; the next combination applies at once. The global shortcut works while
Boltwarden is running, including while the vault is locked; use the installer's
sign-in option to start the daemon automatically. No shortcut is enabled by default.
Reserved combinations and conflicts show an error and preserve the previous active
shortcut. Escape cancels recording and Backspace clears the shortcut. For manual
setup in another tool, run `boltwarden.exe toggle`. Shortcuts are restored on daemon
startup; if another application has taken the key, Settings shows the failure and
lets you record another combination.

Quick access is also available from the tray and commands above.
Drag the logo or empty header space to move quick access; search text and header
buttons retain their normal behavior.

## Graphics and virtual machines

Windows uses Direct3D 12 through wgpu. If no suitable GPU is available, Windows'
built-in WARP software adapter allows windows to render without VM 3D acceleration.
The Windows build does not require OpenGL. Linux continues to use OpenGL.

For graphics-driver troubleshooting, force software rendering from PowerShell:

```powershell
.\boltwarden.exe quit
$env:BOLTWARDEN_SOFTWARE_RENDERING = '1'
.\boltwarden.exe window
```

The variable applies to processes started from that shell. Window startup errors
appear in a dialog; Ctrl+C copies the error for a bug report. CI checks that both
the popup and vault window open and close with default and forced software rendering,
using only the demo login screen.

## Building

Install Rust 1.98.1 with the MSVC toolchain, Visual Studio C++ Build Tools and
Windows SDK, and Python 3.11+. In PowerShell:

```powershell
$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = '-C target-feature=+crt-static'
$env:PYTHONUTF8 = '1'
python scripts/third-party-notices.py rust THIRD_PARTY_NOTICES.txt
cargo test --locked --target x86_64-pc-windows-msvc --lib -- --test-threads=1
cargo build --locked --release --target x86_64-pc-windows-msvc --bins
python scripts/package-windows.py --binary-dir target/x86_64-pc-windows-msvc/release --iscc 'C:\path\to\Inno Setup 6\ISCC.exe' --output dist
```

CI pins and verifies Inno Setup 6.7.3 before use. The package script validates
x86_64 PE inputs and rejects external VC++/MinGW runtime dependencies. The build
embeds Windows dependency notices and packaging includes them in both downloads.
The native host has its own stdio entry point so browser arguments cannot launch
the GUI accidentally. Browser protocol and vault encryption formats remain shared.

## Release validation

Native MSVC CI is required. Cross-compilation and Wine checks are useful additional
checks, but do not establish Windows 11 compatibility. Before publishing, use the
exact downloaded artifacts on a clean Windows 11 x64 VM without Rust/build tools:

1. Verify checksums; install without elevation and test ZIP extraction from a
   path containing spaces and non-ASCII characters. Confirm no console flashes,
   correct icons/version, tray actions, popup/full-window focus, scaling, and
   behavior across multiple monitors.
2. Use a test account for login, 2FA, sync, edits, offline unlock, and account
   switching. Verify lock, idle timeout, suspend/resume, session disconnect, and
   monitor failure. Check clipboard expiry preserves newer copies and secrets
   are absent from Windows clipboard history/cloud sync.
3. In Chrome, Edge, and Firefox, test discovery, pairing, autofill/TOTP, passkey
   registration/sign-in, reprompt, cancellation, revoke, and reconnect. A forged
   host PID or unpaired profile must never receive secrets.
4. With a second Windows account/session, verify named-pipe access is denied and
   private files cannot be read. Test endpoint squatting and reparse-point paths.
   Verify capture settings on both windows; capture exclusion remains best effort.
5. Verify shortcut activation while locked/unlocked, rebinding, conflict handling,
   Clear, and persistence after restart. Verify optional sign-in autostart, upgrade while running, registration conflict
   refusal, and uninstall. User data must remain; only this installation's
   registrations and startup entry may be removed.

Sign both EXEs before packaging and sign the installer afterward before promoting
Windows support to stable. Regenerate checksums after signing; signing credentials
belong in a protected release environment, never pull-request jobs.
