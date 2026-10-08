# Boltwarden privacy notice

Last updated: 2026-10-08. Maintainer: Menno van Leeuwen.

Boltwarden is an unofficial desktop client and browser extension for Bitwarden
and Vaultwarden. It has no advertising, analytics, or telemetry service operated
by the maintainer. The extension does not send your vault to the maintainer.

## Browser extension

The extension reads relevant page and frame URLs, login, payment, and verification fields,
page titles used for saved logins, and WebAuthn requests. It exchanges this data,
usernames (which can be email addresses), selected passwords, verification codes,
and passkey requests and results with your paired local Boltwarden desktop app
through browser native messaging. This transfer outside the browser is required
for matching, filling, saving, and passkey functionality. Password and passkey
approval and vault access are handled by the desktop app. Filling a password or
verification code gives it to the selected website; passkey private keys remain
in the desktop vault, while public credentials and signed assertions reach the site.

When you select a card in the toolbar popup, the desktop sends its cardholder
name, number, security code, expiry, and brand through native messaging to the
selected HTTPS payment form. Card lists contain only names, brands, and last four
digits. Card details are not saved in extension storage or pending password saves.
Embedded payment frames require explicit destination confirmation. Filling gives
that site the selected payment data; the extension never submits the payment.

The extension persistently stores its pairing identifier and non-extractable
pairing key. It does not keep a complete vault. Matching results and selected
credentials are held in memory. Credentials awaiting a save are temporarily held
in browser session storage so they can survive extension background restarts.
They remain until successfully saved and cleaned up, explicitly discarded, or the
browser session ends. Locking the desktop vault does not discard pending saves
or remove values already filled into a page. Use **Discard** in the extension to
remove a pending save. If cleanup fails, the extension reports that and offers retry.

HTTP pages and cross-origin filling require confirmation. Passkeys are supported
only in eligible HTTPS contexts. Page and navigation metadata are used to prevent
credentials from reaching a changed document; they are not collected as an
analytics history. The extension ships its executable code in its package and
does not download remote executable code.

## Desktop app and network services

The desktop app communicates over HTTPS with your configured Bitwarden or
Vaultwarden server for account authentication, synchronization, and approved vault
changes. The server operator's privacy policy also applies. Your master password
is processed locally for key derivation and verification; encrypted vault items
and derived authentication information are exchanged with the server.

An encrypted refresh session and, if enabled, an encrypted offline vault copy
are stored in your user configuration directory. The unlocked vault is held in
memory. The desktop also stores settings, recent item identifiers, pairing records,
and caches. Local malware with access to your account or a compromised browser
profile is outside the isolation this application can provide.

When **Show website icons** is enabled, public website hostnames from your vault
are sent to your server's icon service (Bitwarden's icon service for Bitwarden
cloud accounts). Disable that setting to stop requests and clear the icon cache.
The action center downloads public two-factor and passkey support lists from
2fa.directory, and the public breach list from Have I Been Pwned; it does not send
your vault's hostnames or other vault data with those list downloads.
If you turn on **Check passwords against breaches**, the desktop app sends the
first 5 hexadecimal characters of the SHA-1 hash of each saved password to the Pwned
Passwords service (api.pwnedpasswords.com) and compares its padded answer locally.
Passwords and full hashes are not sent, and the results are not stored on disk. This
setting is off by default.
These services receive normal connection metadata such as your IP address.

## Controls and removal

You can disable browser integration and revoke browser pairings in desktop
settings, discard pending saves in the extension, disable website icons, disable
the offline copy, or remove the extension. Removing the extension removes its
browser-managed storage. Removing a package does not delete your desktop account
files; sign out or remove those files deliberately when you no longer need them.
Disabling the offline copy deletes that copy. Changes made while offline cannot
reflect server-side revocations until a connection is restored.

For questions, contact Menno van Leeuwen through https://github.com/vleeuwenmenno. Do not
post passwords, vault exports, or personal account data in public issues.
