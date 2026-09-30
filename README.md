# Boltwarden

An unofficial Linux desktop app for Vaultwarden and Bitwarden vaults: a quick
access popup plus a full vault window. It is not affiliated with Bitwarden or the
Vaultwarden project.

Formerly `bw-quick-access`. On first start, Boltwarden moves
`~/.config/bw-quick-access` and `~/.cache/bw-quick-access` to their new names, so the
saved session and settings carry over. Remove the old user service
(`systemctl --user disable --now bw-quick-access.service`) and binary after
installing the new one.

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
- A full vault window with a folder tree, favorites and an action center
- Passkeys shown on items; the editor can remove them after a confirmation

## Install

Requirements:

- Rust/Cargo 1.95 or newer
- Linux desktop session
- systemd user services, if you want autostart

Build a release binary:

```bash
make
```

Install it to `/usr/local/bin/boltwarden`:

```bash
sudo make install
```

Install and start the user service:

```bash
make install-service
```

The service runs:

```bash
/usr/local/bin/boltwarden --daemon
```

`--daemon` starts the tray icon, activation socket, and in-memory vault session
without opening the popup immediately.

## Nix

Build and run directly from the flake:

```bash
nix run git+ssh://git@git.mvl.sh/vleeuwenmenno/boltwarden.git
```

Use it as a flake input:

```nix
{
  inputs.boltwarden.url = "git+ssh://git@git.mvl.sh/vleeuwenmenno/boltwarden.git";
}
```

The default package installs the `boltwarden` binary and a desktop launcher
named `Boltwarden Daemon`. The launcher starts:

```bash
boltwarden --daemon
```

This is useful on desktops where you prefer launching the daemon manually instead
of installing the systemd user service.

Published Gitea releases include an `x86_64-linux` tarball with a bundled
executable and a `.sha256` checksum.

## Usage

Open the quick access popup:

```bash
boltwarden
```

Toggle the popup:

```bash
boltwarden --toggle
```

or:

```bash
boltwarden toggle
```

Open the vault window, or toggle it:

```bash
boltwarden window
boltwarden toggle-window
```

If the daemon is already running, these commands send a message to the daemon
instead of starting a second full instance. The tray menu has an **Open vault
window** entry, and typing `window` in the popup offers the same command.

Wayland apps can't grab global shortcuts, so bind the commands in your compositor.
For Hyprland:

```ini
bind = SUPER, P, exec, boltwarden toggle
bind = SUPER SHIFT, P, exec, boltwarden window
```

The popup uses the `boltwarden` app id and the window `boltwarden-window`,
so window rules for the popup (floating, always on top) don't affect the window.

Typical keybindings:

- `Enter`: login, verify 2FA, open selected result, or copy selected field
- `Up` / `Down`: move through results or fields
- `Right`: open the selected search result
- `Left`: go back from an entry detail view
- `Shift+Enter`: copy the selected search result’s password
- `Ctrl+R`: sync the vault from search
- `Space`: reveal or conceal the selected secret (conceals automatically after 15 seconds)
- `Esc`: hide the popup

## Vault window

The vault window is a resizable browser for the whole vault:

- **Sidebar**: All items, Favorites, the Action center, your folders as a tree, items
  without a folder, Archived and Recently deleted. Bitwarden nests folders by name
  (`Work/Servers` sits inside `Work`); a folder lists the items of its subfolders
  too. Click the arrow next to a folder to collapse it.
- **Item list**: sorted by name, last edit or creation date. A search keeps the
  relevance order and applies within the selected section.
- **Item view**: the same fields, copying, reveal and actions as the popup. `F` or
  the star toggles a favorite. The editor can also move an item to another folder.
- **Moving items**: drag an item from the list onto a folder, onto **No folder** to
  take it out of its folder, or onto **Favorites** to star it. Moving works for every
  item, including ones with master-password reprompt, and reveals nothing.
- **Folders**: the `+` next to FOLDERS creates one (`Work/Servers` nests it).
  Right-click a folder for **New subfolder**, **Rename** and **Delete**. Renaming
  renames its subfolders too; change the part before a `/` to move a folder under
  another parent. Deleting removes the folder and its subfolders after a confirmation
  (`Ctrl+Enter`); their items stay in the vault without a folder.

Keys: `Up`/`Down` move through the list, `Ctrl+F` searches, `Ctrl+N` creates an
item (in the selected folder), `Ctrl+R` syncs and `Ctrl+L` locks. With no input
focused, the item view keeps its keys (`Enter` copies, `E` edits, `Del` trashes).

Closing the window with unsaved edits asks first. It runs as its own process next to
the popup and locks together with it.

### Action center

The action center checks active logins for reused passwords, weak passwords (zxcvbn
score below 3), websites saved with `http://` (local network addresses excepted),
duplicate logins (same website, username and password), and cards that expired or
expire within 30 days. The score is the share of passwords with none of the first
three problems. Each card lists its items.

It also suggests sites that offer two-factor login when no one-time code is saved,
and sites that support passkeys when none is stored. Those two checks download the
public [2fa.directory](https://2fa.directory) lists whole, so no vault data or
hostnames leave the machine. The lists are cached for a day in
`~/.cache/boltwarden/2fa-directory.json`; without network access the two cards
show as unavailable. All checks run in the daemon: the window only receives item ids.

### Passkeys

Items show their passkeys (user and site, and when it was saved) in the popup and the
window. Passkeys can't be copied or created here. In the editor, the trash icon next
to a passkey removes it after a confirmation (`Ctrl+Enter` or the button; a plain
`Enter` does not confirm). The passkey is deleted from the vault only when you save
the item; other passkeys go back to the server unchanged.

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
BW_SERVER=https://vault.example.com boltwarden
```

After a successful login, the app stores the refresh session in:

```text
~/.config/boltwarden/session.json
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
`~/.config/boltwarden/settings.json` to use manual locking. Session selection
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
systemctl --user status boltwarden.service
```

Restart the daemon:

```bash
systemctl --user restart boltwarden.service
```

Stop the daemon:

```bash
systemctl --user stop boltwarden.service
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
sudo make install PREFIX=/opt/boltwarden
make install-service PREFIX=/opt/boltwarden
```

This installs the binary to:

```text
/opt/boltwarden/bin/boltwarden
```

and writes the user service to:

```text
~/.config/systemd/user/boltwarden.service
```

## Development

Tests require `dbus-daemon` for an isolated D-Bus integration fixture. They do not
use the real desktop session bus. Run checks:

```bash
make check
RUST_TEST_THREADS=1 make test
```

Try the popup or the vault window with made-up data and no vault:

```bash
BOLTWARDEN_DEMO=1 boltwarden --popup
BOLTWARDEN_DEMO=1 boltwarden --vault-window
BOLTWARDEN_DEMO=action boltwarden --vault-window   # opens on the action center
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
