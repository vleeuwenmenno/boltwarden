# bw-quick-access

A small Linux quick-access GUI for Bitwarden and Vaultwarden vaults.

The goal is to provide a 1Password-style quick access window: open it from a
keyboard shortcut or tray icon, search your vault, open an entry, and copy the
field you need without switching to a full password manager window.

This project talks to the Bitwarden/Vaultwarden HTTP API directly. It does not
shell out to the `bw` CLI.

## Features

- Native Rust desktop GUI using `egui`/`eframe`
- Bitwarden and Vaultwarden login
- Two-factor login with authenticator codes or YubiKey OTP; other methods are shown as unsupported
- Saved refresh session for restart-friendly unlock
- Long-running daemon with a tray icon
- Popup window that can be opened, hidden, or toggled by command
- Search-first workflow with keyboard navigation
- Title-prioritized search results
- Entry detail view with username, password, URI, notes, custom fields, and TOTP
- Copy selected fields from the keyboard or mouse
- Optional SSH agent socket for official Bitwarden/Vaultwarden SSH key items
- Auto-hide on Escape and focus loss, with confirmation before discarding edits
- Random password generation, masked TOTP seeds, and timed secret reveal
- Manual and periodic vault synchronization

## Install

Requirements:

- Rust/Cargo 1.95 or newer
- Linux desktop session
- systemd user services, if you want autostart

Build a release binary:

```bash
make
```

Install it to `/usr/local/bin/bw-quick-access`:

```bash
sudo make install
```

Install and start the user service:

```bash
make install-service
```

The service runs:

```bash
/usr/local/bin/bw-quick-access --daemon
```

`--daemon` starts the tray icon, activation socket, and in-memory vault session
without opening the popup immediately.

## Nix

Build and run directly from the flake:

```bash
nix run git+ssh://git@git.mvl.sh/vleeuwenmenno/bw-quick-access.git
```

Use it as a flake input:

```nix
{
  inputs.bw-quick-access.url = "git+ssh://git@git.mvl.sh/vleeuwenmenno/bw-quick-access.git";
}
```

The default package installs the `bw-quick-access` binary and a desktop launcher
named `Bitwarden Quick Access Daemon`. The launcher starts:

```bash
bw-quick-access --daemon
```

This is useful on desktops where you prefer launching the daemon manually instead
of installing the systemd user service.

Published Gitea releases include an `x86_64-linux` tarball with a bundled
executable and a `.sha256` checksum.

## Usage

Open the quick access popup:

```bash
bw-quick-access
```

Toggle the popup:

```bash
bw-quick-access --toggle
```

or:

```bash
bw-quick-access toggle
```

If the daemon is already running, these commands send a message to the daemon
instead of starting a second full instance.

Typical keybindings:

- `Enter`: login, verify 2FA, open selected result, or copy selected field
- `Up` / `Down`: move through results or fields
- `Right`: open the selected search result
- `Left`: go back from an entry detail view
- `Shift+Enter`: copy the selected search result’s password
- `Ctrl+R`: sync the vault from search
- `Space`: reveal or conceal the selected secret (conceals automatically after 15 seconds)
- `Esc`: hide the popup

## Vaultwarden

On first login, enter your Vaultwarden server URL in the server field, for
example:

```text
https://vault.example.com
```

Server URLs must use HTTPS, including local servers. Credential-bearing redirects
are disabled; enter the final server URL directly.

You can also set a default server with:

```bash
BW_SERVER=https://vault.example.com bw-quick-access
```

After a successful login, the app stores the refresh session in:

```text
~/.config/bw-quick-access/session.json
```

The daemon keeps the unlocked vault in memory while it is running. The popup can
close and reopen without forcing another master-password prompt.

## SSH Agent

The built-in SSH agent is disabled by default. Open the `Settings` quick command
inside the popup to enable it and configure the socket path. The default is:

```text
$HOME/.bitwarden-ssh.sock
```

When enabled, the daemon creates the socket only while the vault is unlocked and
exposes official SSH key vault items through its own Bitwarden/Vaultwarden API
sync; Bitwarden Desktop is not required. Configure your shell or desktop session
to use it:

```bash
export SSH_AUTH_SOCK="$HOME/.bitwarden-ssh.sock"
```

SSH key items can be searched and viewed in the popup, including the public key
and Bitwarden fingerprint/signature value.

SSH signing always requires approval unless the same process was approved for that
key within the last 15 minutes. Remembered approvals bind to PID, process start
time, executable, command line, and working directory. They do not authorize other
processes launched from the same directory. Keys with master-password reprompt
enabled are excluded from the agent. Only Ed25519 and ECDSA keys are advertised.
RSA agent signing is disabled because the upstream `rsa` crate has no patched
release for [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html).
RSA items remain readable and copyable in the vault UI.

## Security behavior and limits

The daemon clears the popup's displayed data and invalidates pending UI responses
when the vault locks. Protected items require master-password verification before
viewing, copying, or editing. Verification expires after 60 seconds; the popup
conceals the item slightly earlier and preserves an unsaved draft behind the
verification screen. Locking the vault discards drafts.

Clipboard ownership expires after 45 seconds and is released when the vault
locks or the daemon quits. The daemon stops only its own foreground clipboard
provider, preserving newer copies from other applications. Wayland requires
`wl-copy`; X11 requires `xclip` or `xsel`. Clipboard managers can retain previously
copied values, especially on X11: expiry cannot erase those independent histories.

On Hyprland, **Settings → Obscure in screen captures** controls whether the popup
is hidden in screenshots and screen sharing. It defaults to on, applies immediately,
and is saved for later launches. Turn it off when capturing the app, then turn it
back on. The toggle changes only this popup's compositor property, not desktop
window rules. It is unavailable on other compositors. Demo mode starts with it off.
This is compositor capture protection, not protection against cameras or privileged
capture tools. Keep a matching `no_screen_share` window rule for protection while
a new popup is mapping, before its saved preference is applied.

Settings and two-step login method lists scroll the selected row into view when
navigating with Up/Down, including when wrapping between the first and last rows.

Screen-lock and idle detection use the system D-Bus `org.freedesktop.login1`
service, including compatible elogind installations. Lock requests, locked-hint
changes, and suspend requests trigger locking. Idle deadlines advance on a
five-second timer without launching subprocesses. The monitor reconnects when the
service restarts and subscribes before reading initial session state.

If automatic locking is enabled and monitoring becomes unavailable, the vault
locks and a warning appears. Systems without a compatible login service must
explicitly disable `lock_on_system_lock` and `lock_after_idle_timeout` in
`~/.config/bw-quick-access/settings.json` to use manual locking. Session selection
requires the daemon's login session or one unambiguous active graphical session.
Desktop environments must report their lock/idle state to the login service.

Secret buffers, keys, editor drafts, and transport buffers are wiped in targeted
paths. Core dumps and ordinary process tracing are disabled at startup. This does
not guarantee that every temporary copy or toolkit allocation is wiped, and does
not prevent privileged memory access or swapping.

Saved refresh sessions use atomic replacement and file mode `0600`. Refresh tokens
are encrypted and authenticated with AES-256-CBC/HMAC-SHA256 under a separate key
derived from the vault key using HKDF-SHA256, bound to the account and server.
Reading the session file alone no longer yields a usable refresh token; unlocking
requires the master password. Account metadata and KDF parameters remain readable.
No OS keyring service is required.

Existing plaintext sessions migrate after the first successful unlock with the
new binary. Refresh-token rotation also updates the encrypted session. Failed
writes report an error; there is no plaintext fallback. Previous backups of a
legacy session are not rewritten, and this does not protect a weak master password
against offline guessing.

The editor generates 24-character random passwords from an unbiased 64-character
alphabet (144 bits of entropy). Passphrase generation and card/identity editors
are not implemented. Vault sync runs approximately every 60 seconds while the
search screen is active; a failed sync keeps cached results and shows a warning.
A muted footer label shows sync state. Hover for the last-sync time; click it or
press `Ctrl+R` to sync manually.

## Service Management

Check service status:

```bash
systemctl --user status bw-quick-access.service
```

Restart the daemon:

```bash
systemctl --user restart bw-quick-access.service
```

Stop the daemon:

```bash
systemctl --user stop bw-quick-access.service
```

Remove the service:

```bash
make uninstall-service
```

Remove the installed binary:

```bash
sudo make uninstall
```

## Custom Install Paths

The Makefile supports the usual `PREFIX` override:

```bash
make
sudo make install PREFIX=/opt/bw-quick-access
make install-service PREFIX=/opt/bw-quick-access
```

This installs the binary to:

```text
/opt/bw-quick-access/bin/bw-quick-access
```

and writes the user service to:

```text
~/.config/systemd/user/bw-quick-access.service
```

## Development

Tests require `dbus-daemon` for an isolated D-Bus integration fixture. They do not
use the real desktop session bus. Run checks:

```bash
make check
RUST_TEST_THREADS=1 make test
```

Build a debug binary:

```bash
make build
```

Build a release binary:

```bash
make release
```

## Notes

- This is currently Linux-focused.
- The app intentionally avoids the Bitwarden CLI because the GUI needs a stable,
  low-overhead daemon/session model.
- `cargo fmt` may not be installed with every Rust toolchain; install
  `rustfmt` if you want formatter support.
