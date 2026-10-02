# README screenshots

These are real app captures using the in-memory `BOLTWARDEN_DEMO` backend.
All accounts, credentials, keys, and verification codes are fictional. The demo
uses Alex Example and `example.com`; no real vault is opened for these captures.

To refresh them, build the app with `cargo build --locked`, then launch:

- `BOLTWARDEN_DEMO=1 target/debug/boltwarden --vault-window` for the full vault.
- `BOLTWARDEN_DEMO=1 target/debug/boltwarden --popup` for quick access.
- `BOLTWARDEN_DEMO=action target/debug/boltwarden --vault-window` for vault health.

Use temporary `XDG_CONFIG_HOME` and `XDG_CACHE_HOME` directories, disable website
icons and capture protection in that temporary demo configuration, and capture
only the demo window. Never disable protection on a real vault for this purpose.
Inspect every image for overlapping windows, notifications, personal information,
and clipping before replacing the PNGs. Keep passwords and recovery codes masked.
