# Release preparation

## CI and artifacts

GitHub Actions replaces the former Gitea release workflow. Push this repository to
[github.com/vleeuwenmenno/boltwarden](https://github.com/vleeuwenmenno/boltwarden)
with Actions enabled; changing CI files does not migrate the repository or
change its Git remote. CI runs on pull requests, pushes to `main`/`master`, tags
matching `v*` (desktop) or `extension-v*` (browser extension), and manual dispatches.

To save runner minutes, a small `changes` job (`scripts/ci-changes.py`) routes work:
documentation-only changes (`docs/**`, root `*.md`) run no other jobs; extension-only
changes run only the `extensions` job; desktop changes run security, Linux, Windows and
macOS.
Files the desktop build embeds from the extension (`extension/public`,
`extension/protocol`, `extension/lib/browser-identities.json`), workflow files and
`LICENSE` trigger everything. Skipped jobs count as passing for required checks.
Tags and manual runs skip routing: `v*` runs desktop jobs, `extension-v*` runs the
extension job, and manual dispatch runs both.

The native `ubuntu-24.04` and `ubuntu-24.04-arm` jobs build in a Debian 12 container
with Rust 1.98.1. Each runs Rust tests, then produces a release tarball, `.deb`,
`.pkg.tar.zst`, and `.rpm` with SHA-256 checksums. Each CPU job then installs the
Debian and Fedora packages in clean Debian 12 and Fedora 44 containers, checks
native-host startup, and removes each package. Fedora also checks RPM integrity,
RC version ordering, dynamically loaded desktop libraries, and the absence of
package scripts that could enable services. Full graphical-session testing is
still a separate manual check.
These are dynamically linked Linux binaries. They require glibc 2.36+
and the desktop libraries listed in package metadata (Debian 12+ or Ubuntu 24.04+
are suitable baselines). ARM64 package architecture is `arm64` on Debian and
`aarch64` on Arch Linux ARM and Fedora. Arch Linux itself targets x86_64.
RPM support was added after the published RC1. New builds attach both RPMs and
their checksums; the existing RC1 release remains unchanged. Fedora 44 is the
tested RPM baseline. Other RPM distributions, including older RHEL/CentOS
systems, are not covered by these tests and may not meet the glibc requirement.

The `windows-x86_64` job runs on `windows-2025` with Rust 1.98.1 and the
`x86_64-pc-windows-msvc` target. It runs Windows/shared Rust tests, generates
Windows dependency notices, and builds the GUI and native-host EXEs with static
CRT linkage. A version-pinned, SHA-256-verified Inno Setup 6.7.3 compiler produces
a per-user installer. Packaging checks PE architecture and imported runtime DLLs.
The same application payload is also packaged as a ZIP; both have checksums.
The smoke test runs only on a disposable CI account and refuses existing app data.
It opens both GUI windows with default and forced WARP software rendering using
synthetic demo data, then checks native-host framing, registration, singleton activation, installation,
upgrade while running, optional sign-in/browser tasks, and uninstall while
preserving user data.

The `macos-universal` job runs on `macos-15` with Rust 1.98.1 and both
`aarch64-apple-darwin` and `x86_64-apple-darwin` targets. It runs the Rust tests,
generates dependency notices, builds both architectures, and packages
`boltwarden-VERSION-universal-macos.zip` with `scripts/package-macos.py`: one
`Boltwarden.app` whose executables are merged with `lipo`, signed ad hoc (there is no
Developer ID), and zipped with `ditto`, plus a checksum. `scripts/macos-smoke.py` then
extracts the ZIP, verifies the signature strictly, checks that both executables are
universal and that the bundle version matches, and runs `--version`. Users approve the
unsigned app once on first launch; see [macOS](macos.md).

Windows assets are unsigned previews, including on stable desktop tags. Do not
advertise stable Windows support until both EXEs and the installer are signed
and the Windows 11 checks in [Windows validation](windows.md#release-validation)
have passed. Hosted Windows Server tests do not certify Windows 11 desktop behavior.
Existing published releases are unchanged; release the new assets under a new tag.

A separate container checks npm dependencies, types, unit tests, playground tests,
and real Chromium/Firefox integration fixtures, then exports Chrome/Firefox ZIPs
and the AMO source ZIP. CI uploads them as separate `extension-chrome`,
`extension-firefox`, and `extension-sources` artifacts, each containing one ZIP
and its checksum. Extension tags (`extension-vX.Y.Z`, matching `extension/package.json`) attach the ZIPs
and checksums to their own draft release; desktop releases do not include them. All browser tests use disposable profiles and synthetic
credentials. They do not use a real vault. The source ZIP contains the license,
source code, lockfile, tests, and reviewer build instructions.
The Firefox passkey fixture repeats same-URL navigation ten times to exercise
document timing and policy binding. If Firefox reports ambiguous timing, the fixture
checks that fallback makes no vault assertion request and cancels the native prompt.
It still requires explicit desktop-denial coverage. For a longer local stress run, set
`BOLTWARDEN_FIREFOX_NAVIGATIONS=100` when running `tests/passkey-firefox-e2e.mjs`
from the extension directory after building it.

Security checks include formatting and `cargo audit --deny warnings`. No advisory
is globally ignored. Dependabot proposes dependency, action, and container updates.
Nix flake outputs cover both CPUs, but the distribution workflows build through
Docker; Nix builds need separate validation if their expressions or lockfile change.

The desktop version of a release comes from its tag. Tag builds run
`scripts/set-version.py`, which stamps the tag's version into `Cargo.toml` and
`Cargo.lock` inside the CI checkout before testing and packaging; the change is
never committed. The version in `Cargo.toml` applies only to local and untagged
builds and does not need a bump per release. `v1.0.0-rc.2` was pushed before this
change and failed the release check; it has no release and is not reused.
The extension version is numbered independently. Existing tags are never moved.
Supported desktop versions are `X.Y.Z` and `X.Y.Z-rc.N`, with N starting at 1.
Tarballs retain the desktop version; Debian maps RCs to `X.Y.Z~rc.N` and Arch to
`X.Y.ZrcN-1` so final releases sort newer. Package-order regression tests exercise
`dpkg` and `vercmp` when those tools are installed.
RPM also uses `X.Y.Z~rc.N` internally, with Release `1`; its download filename is
`boltwarden-X.Y.Z-rc.N-1.x86_64.rpm` (or `aarch64`) to avoid GitHub rewriting `~`.
Debian download filenames retain the desktop version (for example,
`boltwarden_1.0.0-rc.1_amd64.deb`), while their internal Version field uses
`1.0.0~rc.1`. GitHub rewrites `~` in asset names, so it must not appear in filenames.
The release job downloads its uploaded assets and verifies the inventory and
checksums again to catch hosting-side name changes.

The initial RC1 upload exposed this GitHub rewrite. Its draft Debian downloads
were renamed and their checksum sidecars regenerated without changing package
contents or moving the tag. Re-running RC1's original tagged release workflow
would restore the old names; use this corrected packaging workflow for later tags.

A release tag must be `v` plus a supported version, such as `v1.0.0-rc.3`. Chrome
extension versions remain numeric; do not copy the desktop RC suffix into the
extension manifest. Curated release notes at `docs/release-notes-VERSION.md` are
optional; without them the draft lists merged pull requests generated by GitHub,
which can be edited before publishing. The release job checks
all ten expected desktop artifacts and their checksums, rejecting missing or extra files.
RC tags create drafts marked as prereleases; stable tags create ordinary drafts.
Only after every job succeeds does the workflow create a **draft** GitHub release
and attach both architectures’ binaries/packages, Windows installer/ZIP, and their
checksums. Extension tags create a separate draft with the Chrome and Firefox ZIPs, the
AMO source ZIP and their checksums. Missing artifact groups fail the release job. Existing draft assets with the same names are replaced on a rerun; published
release assets are never overwritten. The workflow does not publish the draft or
submit to extension stores.

## Local verification

```sh
make help
make test security
make extension-check extension-test extension-zip extension-release-check
python3 -m unittest discover -s scripts/tests
# Same build as native CI; exports artifacts under dist/.
make package
# Installation checks for the native packages just built.
docker buildx build -f packaging/Dockerfile.smoke dist
docker buildx build -f packaging/Dockerfile.fedora-smoke dist
# Full extension build and browser fixtures in the CI image.
docker buildx build -f packaging/Dockerfile.extension --output type=local,dest=dist .
```

Cargo-audit 0.22.2 must be installed for `make security`; it needs network access to
RustSec/crates.io. npm audit needs its registry. Docker builds need access to image
registries, Debian/Fedora repositories, crates.io, and npm. Local tests require D-Bus and
permission to open local sockets. Test fixtures run with one Rust test thread.

For a native distro-built ELF binary, `python3 scripts/package-release.py --binary
/path/to/boltwarden` packages without recompiling. It requires Python 3.11+, readelf,
dpkg-deb, rpmbuild, and zstd. It detects architecture from the ELF header and refuses binaries
linked to Nix store paths. Use Docker for release binaries to enforce the ABI baseline.
Checksums use basenames: run `sha256sum --check ./*.sha256` from inside `dist`.

## Installation and service checks

On a clean Debian/Ubuntu machine, install the matching `.deb` with `sudo apt install
./boltwarden_*.deb`. On Arch/Arch Linux ARM, use `sudo pacman -U ./boltwarden-*.pkg.tar.zst`.
On Fedora, use `sudo dnf install ./boltwarden-*.rpm` with the matching CPU package.
DNF resolves dependencies from Fedora's repositories. RPMs are currently unsigned
and distributed with SHA-256 checksums; there is no Boltwarden DNF/YUM repository
or automatic package update channel. Installing a newer downloaded RPM uses the
same command. Remove it with `sudo dnf remove boltwarden`.
Package installation does not start the app or ask root which user's session to
modify. Autostart is per user: **Start at login** in **Settings → General** writes an
XDG autostart entry to `~/.config/autostart/boltwarden.desktop`, which desktop
environments and systemd-managed sessions (such as uwsm) run at graphical login.
Turn it off before removing a package; a leftover entry is skipped because its
`TryExec` binary is gone. `boltwarden-setup` only offers browser registration. Do not
run it through sudo. Package upgrades do not restart an unlocked running vault
automatically; restart it deliberately after saving any edits.

Before publishing, test installation, upgrade, removal, Start at login on and off,
Wayland and X11 launch, and desktop browser registration on each CPU/distro target.
Test against a disposable real Vaultwarden/Bitwarden account: login, 2FA, lock,
offline unlock, sync, fills, save/update, passkeys, and revocation. Automated fixtures
do not replace real account and desktop checks.

## Store submission

Follow [extension publishing](../extension/PUBLISHING.md). Still needed from the
maintainer: developer accounts, final Chrome store identity, hosted public privacy
URL, genuine screenshots, and final listing review. Never put store signing keys,
refresh tokens, vault credentials, or browser profiles in the repository.

Enable GitHub private vulnerability reporting and protect the default branch with
the single `CI result` check. It waits for every other job and passes when they passed
or were skipped by path routing; requiring the individual jobs instead blocks pull
requests whose skipped matrix jobs never report their matrix names. Inspect a successful workflow
and download/test its exact artifacts before publishing the draft release. The
maintainer must configure the GitHub repository and account permissions; this
working-tree change does not make that external configuration.

## License

Project code uses MIT with Commons Clause v1.0; keep the full LICENSE file and
Menno van Leeuwen's copyright notice in forks and distributions. Internal company
use is permitted. The clause restricts selling products or services whose value
derives entirely or substantially from Boltwarden, including lightly modified
forks and paid hosting. It is not a blanket ban on selling every larger product
that incorporates code. The project is source-available, not OSI open source.
Dependencies keep their own licenses; include required third-party notices when
distributing bundled code. See https://commonsclause.com/ for the exact condition.
