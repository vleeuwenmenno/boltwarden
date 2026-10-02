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
- Experimental Chrome/Chromium and Firefox extension for daemon-backed login filling
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

Build a release binary (`make` alone shows help):

```bash
make release
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

### Distribution packages and autostart

Install the matching release `.deb` with `sudo apt install ./boltwarden_*.deb`,
or an Arch package with `sudo pacman -U ./boltwarden-*.pkg.tar.zst`.
Run `boltwarden-setup` **without sudo** afterward to choose whether Boltwarden
starts at graphical login. Packages install a user service but never enable it
for all users. See [package requirements and verification](docs/releasing.md).

## Nix

Build and run directly from the flake:

```bash
nix run github:vleeuwenmenno/boltwarden
```

Use it as a flake input:

```nix
{
  inputs.boltwarden.url = "github:vleeuwenmenno/boltwarden";
}
```

The default package installs the `boltwarden` binary and a desktop launcher
named `Boltwarden Daemon`. The launcher starts:

```bash
boltwarden --daemon
```

This is useful on desktops where you prefer launching the daemon manually instead
of installing the systemd user service.

GitHub Actions prepares release tarballs, Debian packages, and Arch packages for
`x86_64` and `aarch64`, with SHA-256 checksums. Distribution binaries require
glibc 2.36+ and desktop libraries; they are not self-contained Nix bundles.
Chrome and Firefox ZIPs and the Firefox review source ZIP are also produced.
Firefox ZIPs are unsigned until Mozilla review/signing. See
[release preparation](docs/releasing.md) and [extension publishing](extension/PUBLISHING.md).

The Nix package includes a `boltwarden-native-host` launcher and native messaging
manifests under `lib/mozilla/native-messaging-hosts` and
`etc/chromium/native-messaging-hosts`. For Home Manager, with `boltwardenPackage`
referring to this flake's default package:

```nix
programs.firefox.nativeMessagingHosts = [ boltwardenPackage ];
xdg.configFile."chromium/NativeMessagingHosts/nl.mvl.boltwarden.json".source =
  "${boltwardenPackage}/etc/chromium/native-messaging-hosts/nl.mvl.boltwarden.json";
```

For a NixOS Firefox configuration, use
`programs.firefox.nativeMessagingHosts.packages = [ boltwardenPackage ];` instead.
Google Chrome uses `google-chrome/NativeMessagingHosts` in the Home Manager path.
The browser extension itself still needs to be loaded separately.

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

The vault window remembers its sort order across restarts. Right-click an item to
copy its username or password, edit it, archive it, or move it to trash. Protected
items still require verification, and moving to trash asks for confirmation.

Ctrl-click toggles individual selections; Shift-click selects a range. Drag any
selected item onto a sidebar folder to move the whole selection. Drop onto **No
folder** to remove folder assignments, or **Favorites** to favorite the selection.
Ctrl+A selects all visible items when the search field is not focused.

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

## Offline use

After a successful sync, Boltwarden keeps an encrypted offline copy by default.
With a saved session, you can unlock it without a connection and use search,
quick access, copying, TOTP, the SSH agent, and paired browser filling. Offline access is read-only;
editing, creating, moving, and deleting require a successful sync first.
Press Ctrl+R to reconnect, or let automatic retries run.

The copy lives at `$XDG_CONFIG_HOME/boltwarden/vault-cache.json` (normally
`~/.config/boltwarden/vault-cache.json`), with owner-only permissions. It is
wrapped in authenticated encryption using a separate key derived from your
account key and bound to your account and server. The file contains neither
readable vault metadata nor your master password.

The **Offline** status shows the copy's age on hover. Copies do not expire:
server-side deletions, permission changes, and password changes cannot be known
while disconnected. A confirmed session revocation prevents offline fallback;
an unseen revocation cannot invalidate a disconnected copy. The age records the
last full sync, even when later local edits have updated the copy.

Disable **Keep offline copy** in Settings to delete it. **Use another account**
also deletes it; locking the vault keeps it. A missing or corrupt copy requires
an online sync before offline unlock will work again.

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

## Browser integration

Browser integration supports inline username/email/password suggestions, the toolbar
popup, `Ctrl+Shift+L`, and passkey sign-in and creation on supported HTTPS pages.
Browser TOTP filling is supported. Password save/update prompts are still planned. The desktop
remains the vault owner; the extension has no independently unlocked or persisted
vault.

Integration is **disabled by default**. Enable **Browser integration** in the
desktop Settings, then open **Settings → Browser setup**. Installed browsers are
found without launching them and are initially selected. Choose the browsers you
use and click **Apply**. The same setup panel is available from **Paired browsers**
in the full client. **Add browser** accepts a custom executable, browser family,
and native-host folder. For Chromium browsers, choose the browser data folder's
`NativeMessagingHosts` directory, not a `Default` or `Profile 1` directory.

Registration lets a browser find Boltwarden; it does not grant vault access.
Each extension profile still needs pairing approval. Turning a browser off prevents
new native-host launches; revoke its pairing to end an existing authenticated session.

Alternatively, register the native messaging host for the current user:

```bash
boltwarden install-browser --browser all
```

Supported Linux desktop registrations:

| Browser | Installer choices |
| --- | --- |
| Firefox, Developer Edition, Zen, LibreWolf | `firefox`, `firefox-developer`, `zen`, `librewolf` |
| Chrome, Chromium, Ungoogled Chromium | `chrome`, `chrome-beta`, `chrome-dev`, `chromium`, `ungoogled-chromium` |
| Brave and Brave Origin | `brave`, `brave-beta`, `brave-nightly`, `brave-origin` |
| Opera and Opera GX | `opera`, `opera-beta`, `opera-developer`, `opera-gx` |
| Helium | `helium` |
| Vivaldi | `vivaldi`, `vivaldi-snapshot` |
| Microsoft Edge | `edge`, `edge-beta`, `edge-dev` |

`all` installs the catalog's distinct native-host registrations. Discovery only lists
executables found on PATH. Browsers sharing a native-host folder appear together on
one toggle (for example, **Firefox / Zen**), because their registration cannot be
turned off independently. Their extension profiles still pair separately.

These entries cover native Linux installations. Flatpak/Snap builds and relocated
profiles may require their own native-messaging bridge or custom registration;
being in this catalog does not certify every browser's passkey behavior. Firefox
and Chromium have automated end-to-end extension tests. The catalog has discovery,
manifest, and registration tests for every entry.

Path references: [Chromium native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging),
[Helium Linux branding](https://github.com/imputnet/helium-linux/blob/main/patches/helium/linux/change-chromium-branding.patch),
[Zen native messaging](https://github.com/zen-browser/desktop/issues/10622),
[LibreWolf native messaging](https://librewolf.net/docs/faq/#how-do-i-get-native-messaging-to-work).

Run this as your desktop user, without `sudo`. `--path /absolute/path/to/boltwarden`
selects a stable binary location. The installer writes a launcher to
`~/.local/libexec/boltwarden-native-host` and browser-specific host manifests.
Rerun it after moving the binary. `make install-browser BROWSER_TARGET=firefox` registers
the binary installed through the Makefile. Nix users can use the declarative
registration above instead.

Build the extension with Node.js 22.12 or newer:

```bash
make extension-deps extension-build
```

Brave Origin is discovered separately from Brave and uses
`~/.config/BraveSoftware/Brave-Origin/NativeMessagingHosts`. Choosing a known browser
executable in custom setup suggests its vendor-specific folder.

In Chrome/Chromium or Vivaldi, open the browser's extensions page, enable developer mode, and load
`extension/.output/chrome-mv3` as an unpacked extension. In Firefox, open
`about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**, and select
`extension/.output/firefox-mv3/manifest.json`. Firefox's temporary installation
ends when the browser restarts. A persistent installation requires a separately
signed add-on; this repository does not supply signing credentials.

Open the extension popup and request pairing. Compare its public-key fingerprint
with the desktop approval, then approve in Boltwarden. Each browser profile pairs
separately. Type `browsers` in quick access, open **Settings → Paired browsers**, or choose
**Paired browsers** in the full client sidebar, to review and revoke pairings.
The view uses the same compact rows as the vault list. Select a browser and press
Enter, then confirm revocation with Ctrl+Enter or the button. The full fingerprint,
pairing date, and last authenticated connection are available in the row tooltip
and confirmation.
Revoking a browser requires confirmation, disconnects its active sessions, and
cancels pending requests. It must pair again before accessing the vault. This
view remains available when browser integration is disabled.

The daemon must be running; start it through your installed user service or `boltwarden --daemon`.
Native Linux browser packages are supported initially. Snap/Flatpak browsers and
native messaging portals are not supported in this phase.

### Filling and matching

Focus a username, email, or password field and click its Boltwarden mark (or press
Arrow Down) to see matching logins. Arrow keys move the selection, Enter fills,
and Escape closes suggestions. Tab keeps the page's normal focus order. Inline
suggestions use the same site matching rules as the toolbar and never submit the
form. Registration, new-password, hidden, and one-time-code fields are excluded.
Open shadow roots and dynamically inserted fields are supported.

You can also press `Ctrl+Shift+L` or choose a login in the toolbar popup. A locked
vault opens the desktop unlock flow. Multiple matches require a selection;
protected items still require a fresh desktop master-password check and are not
filled by the shortcut. HTTP pages, cross-origin frames, and matches requiring
confirmation use the toolbar's confirmation flow instead of direct inline fill. Verification in the desktop item viewer does not authorize browser
filling.

The toolbar uses the desktop's split-shield mark. The popup follows the quick
access layout: filter this page's matching logins by name or username, move with
the arrow keys, and press Enter to fill the selected login. Filtering covers
loaded matches; use **Load more matching logins** when further matches are available. Locking,
unlocking, disconnecting, and changing pages update the open popup automatically.

The default match rule is **Host**, comparing normalized hostname and port.
Explicit per-URI Bitwarden rules take precedence; missing rules use the desktop
default. Domain matching includes private public-suffix entries, keeping
`alice.github.io` separate from `bob.github.io`. Regex matching uses a bounded,
case-insensitive Rust regex engine. JavaScript lookaround and backreferences are
unsupported and do not match. Unknown rules fail closed. Archived and deleted
items are excluded.

The destination frame's URL determines matches. The shortcut fills only the top
document or a same-origin frame. Cross-origin frames require an explicit popup
selection and destination confirmation. HTTP destinations that match an HTTPS
entry require confirmation; the shortcut cannot fill them. HTTP regex matches
also require confirmation. A changed document or changed vault item invalidates
the pending fill.

Verification-code fields also support inline, toolbar, and shortcut filling. Select a matching
account with a saved TOTP seed to fill its current code. The selected inline account
shows grouped digits and an expiry countdown; protected accounts remain masked until
verification. Previews clear when the picker closes or the vault locks. Single fields and six/eight-box
forms are supported when their markup identifies them as OTP fields. Codes are generated
in the desktop daemon; seeds are never sent to the extension. Item verification and URI
matching still apply. Expired codes and changed forms are rejected. Boltwarden does not
submit the form or copy codes automatically.

Listing or filling logins follows the daemon's sync schedule: normally after 60
seconds, with retries backing off to five minutes while offline. Connection
failures leave the unlocked local copy available and show a warning in the
extension. Confirmed session revocation locks the vault and cancels pending
fills. There is no separate browser vault to synchronize.

### Browser trust and privacy

The extension persistently stores its pairing key and identifier, not a full
vault. Matching summaries and selected credentials pass through extension memory.
Pending saves temporarily retain usernames and passwords in browser session
storage until saved and cleaned up, explicitly discarded, or the browser session
ends. Locking does not discard these pending saves. Filling necessarily gives
the page its credentials. See the [privacy notice](PRIVACY.md).
Locking the vault clears extension matching state but cannot erase a password
already filled into a website.

Native messaging uses local stdio and an owner-only Unix socket with peer
credential checks. Pairing authenticates an approved browser profile key, not the
integrity of every script or extension in that profile. A compromised paired
extension can request credentials while the vault is unlocked. Local software
running as the same desktop user and privileged processes remain inside the
trusted system boundary. Keep the browser profile and desktop account secure,
and revoke unused pairings.

Remove host registration with:

```bash
boltwarden install-browser --browser all --uninstall
```

This removes registrations for the known browser locations; custom registrations
can be turned off in Browser setup. The shared launcher is retained for custom
browser locations. Remove the extension separately and revoke its pairing from
desktop Settings if that profile should no longer be trusted.

### Local passkey playground

Run `make playground`, then open **https://localhost:8443** in a browser paired
with Boltwarden. Requires the extension's development dependencies (`make
extension-deps`), Node 22.12 or newer, and OpenSSL. Accept the certificate warning
for this local test page; the server generates a self-signed localhost certificate
in the ignored `extension/.playground` directory. It listens on loopback only.

1. Enter a disposable name such as `alice` and click **Create passkey**. Approve
   in Boltwarden. The page independently validates the registration with
   `@simplewebauthn/server`.
2. Click **Sign in** to verify the stored credential's signature. **Choose account**
   tests discoverable sign-in without specifying credential IDs. Add a second
   account to exercise account selection.
3. Keep the server running while restarting Boltwarden, reloading the extension,
   or opening another paired browser, then sign in again. Test options include
   required/preferred/discouraged user verification and 32-byte, 8 KiB, and
   64 KiB challenges. **Cancel** exercises cancellation.
4. **Reset test data** forgets server accounts and outstanding requests. Stopping
   the server does the same. Neither action deletes vault items: remove the
   `boltwarden-test-*` logins from your vault when finished.

This is a disposable development relying party, not an account service. Anyone
using the local page can reset its shared in-memory records. No email, external
account, or mock authenticator is needed for manual use; Boltwarden creates real
test vault items. Private keys remain with the authenticator. Do not expose this
server to the network. To regenerate an expired local certificate, stop the server
and remove `extension/.playground` before starting it again.

Run `npm --prefix extension run test:playground` for verifier and HTTP boundary
tests. The Chromium passkey suite also drives this page through the real extension
with a synthetic native host and verifies creation, sign-in, and discovery using
64 KiB challenges. Manual desktop approval and server sync still need the steps
above; the automated browser test does not use your vault.

### Password save and update

New-password fields offer **Use suggested password** in the existing inline
Boltwarden menu (icon or Down arrow). The extension generates a password locally
with cryptographic randomness, fills new-password and confirmation fields in the
same form, and leaves current-password fields alone. Suggestions default to 20
characters. Choose random passwords (8–128 characters), memorable passwords
(4–12 words, default 6), or PIN codes (4–128 digits, default 6), and configure
numbers and symbols where applicable. Memorable passwords use the EFF Long
Wordlist with unbiased random selection; symbols choose hyphens instead of spaces.
Field length limits are checked without truncating a generated password. Tab opens
the generator controls; Escape closes them. Suggestions are not saved or sent to
the desktop until a form is submitted. **Generate another** replaces the suggestion;
closing the menu discards an unused suggestion.

Submitting a standard HTML password form on a top-level HTTPS page offers desktop
approval to save its credentials. Choose **Create new login** or select a matching
editable personal login, then **Save password**. Existing-item updates preserve
passkeys, TOTP, URIs, notes, custom fields, and password history; a missing username
on a password-only change form does not erase the saved username. Protected items
require fresh master-password verification. An unchanged matching username/password
is ignored without prompting. If the vault is locked, the extension retains the
submitted credentials and requests unlock, then resumes the save approval. Failed
or cancelled saves remain in the extension popup with **Retry save** and **Discard**.
Pending credentials use extension-only `storage.session` memory so background-worker
suspension does not lose them. They are removed after saving or explicit discard,
and are lost when the browser session ends or the extension is reloaded/disabled.
They are never written to `storage.local`, synced storage, or the page.

Capture supports login, registration, and password-change forms with explicit new
password fields; confirmation fields must agree. It requires a recent real click
or key event and a browser submit event. HTTP, iframe, non-form JavaScript-only,
and ambiguous password forms are not captured. The prompt describes submitted
credentials, not a verified successful login: a website may still reject them.
Locked/offline vaults must be unlocked/reconnected before resubmitting. Shared
organization items are not offered for browser writes yet.

In the playground's **Password save and update** section, register a made-up
password and matching confirmation (or use a Boltwarden suggestion), then approve
a new login after submission. Switch to **Change password**, provide the old
and new values, and select that login in Boltwarden. Use **Sign in** to check the
updated value. Then create a passkey for the same test name above and select the
same login. Verify both password and passkey sign-in still work. Playground
passwords are salted and hashed in memory; reset/stop forgets them along with
server passkey records, without deleting vault items.

### Remaining browser work

Pairing, username/password filling, and an initial passkey profile are implemented.
Remaining work includes wider password-form coverage, wider WebAuthn compatibility,
signed Firefox/Chrome distribution, and
sandboxed-browser packaging validation.

### Passkeys

On a supported page, the site's normal **Create a passkey** or **Sign in with a
passkey** button opens desktop approval. Select an account when several match,
then approve. **Settings → Passkey verification** controls the master-password
prompt:

- **Always ask** (the default) requires fresh password verification for every operation.
- **Only when required** asks when the website requires user verification or the
  selected item has master-password reprompt enabled. Optional requests use approval
  alone and report that user verification was not performed.
- **Use vault unlock** reuses the password verification that opened the current
  vault session. Choose an account and approve without retyping the password, even
  when the website requires user verification. Items with master-password reprompt
  enabled still require fresh verification.

**Use vault unlock** reports user verification based on that authenticated session,
not a fresh password or biometric check for each passkey operation. Reuse ends when
the vault locks, the account changes, or the daemon restarts; it is never persisted
as a separate grant. This is an opt-in session policy, not a claim of FIDO-certified
verification caching. A locked vault still needs unlocking, and changing the
setting cancels pending browser requests. **Other device**
returns control to the browser's usual authenticator chooser; **Deny** stops
the request. Reload tabs that were open before installing or updating the extension.

Sign-in supports Bitwarden-format ES256/P-256 credentials with a zero signature
counter. Account selection is limited to the requesting relying party and any
credential IDs requested by the site. For new passkeys, desktop approval offers a new personal login or a matching
editable personal login. Adding to an existing login preserves its password,
URIs, fields, and previous passkeys. Protected items require fresh password
verification, and a changed item revision invalidates the selection. Registration returns success only after
the encrypted server save succeeds. Sign-in can use available offline vault data;
creation requires a working server connection. If the site cancels after a save
commits, the saved credential remains in the vault.

The initial profile supports loaded top-level HTTPS pages, discoverable credentials,
`none` attestation, and the `credProps` extension. UI hints and optional legacy
`appid` inputs do not exclude normal RP-scoped passkeys; Boltwarden ignores AppID
and leaves legacy U2F credentials to the browser. Iframes, conditional/autofill
mediation, other algorithms, nonzero counters, extra WebAuthn extensions (including
PRF and large blobs), and unsupported attestation requests use the browser's
native flow. New credentials use Bitwarden's syncable backup flags and zero-counter
profile. Imported credentials with different backup semantics are not supported.
Requests wait within their timeout for verified DOM readiness; slow subresources
do not force native fallback. Requests whose document cannot be verified fall back
to native WebAuthn near their deadline. The extension does not claim a platform authenticator through WebAuthn's static
capability checks. Sites that require browser-internal credential slots or gate
all passkey use on those checks may need the native flow.

The daemon constructs the relying-party hash and signed client data from the
validated requesting context. Private keys stay in the daemon. Cancellation,
navigation, account changes, lock, pairing revocation, and request deadlines are
checked before releasing responses. The browser bridge observes Permissions-Policy
and delegates to native WebAuthn when it cannot establish permission.

Format verification uses pinned
[Bitwarden authenticator source and public fixtures](https://github.com/bitwarden/clients/blob/1402df876fa11c9be454ec18ef8484121024db38/libs/common/src/platform/services/fido2/fido2-authenticator.service.spec.ts),
[the encrypted vault schema](https://github.com/bitwarden/sdk-internal/blob/933b41024148911736942486b862c1e7d0ef0aeb/crates/bitwarden-vault/src/cipher/login.rs),
and [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/). Tests cover encrypted
server round trips and independently verify signatures using Node/OpenSSL.
A live round trip through an official Bitwarden client remains a separate
compatibility check; these tests do not claim one.

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
alphabet (144 bits of entropy). Desktop passphrase generation and card/identity
editors are not implemented; the browser inline generator supports passphrases. Vault sync runs approximately every 60 seconds while the
search screen is active, or on browser listing/fill requests once the same interval
has elapsed; a failed sync keeps cached results and shows a warning.
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
make release
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

Browser development uses an optional Nix shell with Node.js:

```bash
nix develop .#extension
make extension-deps
make extension-check extension-test extension-build
make extension-zip
```

`extension-zip` creates Chrome, Firefox, and Firefox review source ZIPs in
`extension/.output`. `npm --prefix extension run dev` and
`npm --prefix extension run dev:firefox` start WXT's browser development modes.
The fixed development identities are `lalifhibgahkeifiadipppebhbigoppp` for Chrome
and `boltwarden@mvl.sh` for Firefox; production store identities must be coordinated
with the native host allowlist before release.

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

## Release and project policies

See [security](SECURITY.md), [privacy](PRIVACY.md),
[release preparation](docs/releasing.md), and [extension publishing](extension/PUBLISHING.md).

Boltwarden is source-available under [MIT with Commons Clause v1.0](LICENSE).
Internal business use is permitted; selling products or services based substantially
on Boltwarden is restricted. Forks and distributions must retain Menno van Leeuwen’s
copyright notice and the complete license. Third-party dependencies keep their own licenses.

Credit cards can be selected from the extension toolbar on HTTPS payment forms
with standard `cc-*` autocomplete fields. The popup displays masked card numbers;
fills require explicit selection and never submit payments. See the
[browser extension guide](extension/README.md#credit-card-autofill).
