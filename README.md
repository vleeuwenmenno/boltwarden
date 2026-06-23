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
- Two-factor login support for standard provider responses
- Saved refresh session for restart-friendly unlock
- Long-running daemon with a tray icon
- Popup window that can be opened, hidden, or toggled by command
- Search-first workflow with keyboard navigation
- Title-prioritized search results
- Entry detail view with username, password, URI, notes, custom fields, and TOTP
- Copy selected fields from the keyboard or mouse
- Auto-hide on Escape and focus loss

## Install

Requirements:

- Rust/Cargo
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
- `Esc`: hide the popup

## Vaultwarden

On first login, enter your Vaultwarden server URL in the server field, for
example:

```text
https://vault.example.com
```

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

Run checks:

```bash
make check
make test
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
