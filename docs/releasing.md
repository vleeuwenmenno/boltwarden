# Release preparation

## CI and artifacts

GitHub Actions replaces the former Gitea release workflow. Push this repository to
[github.com/vleeuwenmenno/boltwarden](https://github.com/vleeuwenmenno/boltwarden)
with Actions enabled; changing CI files does not migrate the repository or
change its Git remote. CI runs on pull requests, pushes to `main`/`master`, tags
matching `v*`, and manual dispatches.

The native `ubuntu-24.04` and `ubuntu-24.04-arm` jobs build in a Debian 12 container
with Rust 1.95.0. Each runs Rust tests, then produces a release tarball, `.deb`,
and `.pkg.tar.zst` with SHA-256 checksums. Each CPU job then installs the Debian
package in a clean container, checks native-host startup, and removes the package.
These are regular dynamically linked
Linux binaries, not the old self-extracting Nix bundles. They require glibc 2.36+
and the desktop libraries listed in package metadata (Debian 12+ or Ubuntu 24.04+
are suitable baselines). ARM64 package architecture is `arm64` on Debian and
`aarch64` on Arch Linux ARM. Arch Linux itself targets x86_64.

A separate container checks npm dependencies, types, unit tests, playground tests,
and real Chromium/Firefox integration fixtures, then exports Chrome/Firefox ZIPs
and the AMO source ZIP. All browser tests use disposable profiles and synthetic
credentials. They do not use a real vault. The source ZIP contains the license,
source code, lockfile, tests, and reviewer build instructions.
The Firefox passkey fixture repeats same-URL navigation ten times to exercise
document timing and policy binding. For a longer local stress run, set
`BOLTWARDEN_FIREFOX_NAVIGATIONS=100` when running `tests/passkey-firefox-e2e.mjs`
from the extension directory after building it.

Security checks include formatting and `cargo audit --deny warnings`. No advisory
is globally ignored. Dependabot proposes dependency, action, and container updates.
Nix flake outputs cover both CPUs, but the distribution workflows build through
Docker; Nix builds need separate validation if their expressions or lockfile change.

The prepared versions are desktop 0.4.1 and extension 0.5.6. The local `v0.4.0`
tag already exists; the next desktop tag is `v0.4.1`. Do not move the old tag.
Confirm extension 0.5.6 has not already been used in either store before submission.

A `vX.Y.Z` tag must match Cargo.toml. Desktop and extension versions are independent:
verify the extension version is greater than the last version in each store.
Only after every job succeeds does the workflow create a **draft** GitHub release
and attach artifacts. Existing draft assets with the same names are replaced on a rerun; published
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
# Full extension build and browser fixtures in the CI image.
docker buildx build -f packaging/Dockerfile.extension --output type=local,dest=dist .
```

Cargo-audit 0.22.2 must be installed for `make security`; it needs network access to
RustSec/crates.io. npm audit needs its registry. Docker builds need access to image
registries, Debian repositories, crates.io, and npm. Local tests require D-Bus and
permission to open local sockets. Test fixtures run with one Rust test thread.

For a native distro-built ELF binary, `python3 scripts/package-release.py --binary
/path/to/boltwarden` packages without recompiling. It requires Python 3.11+, readelf,
dpkg-deb and zstd. It detects architecture from the ELF header and refuses binaries
linked to Nix store paths. Use Docker for release binaries to enforce the ABI baseline.
Checksums use basenames: run `sha256sum --check ./*.sha256` from inside `dist`.

## Installation and service checks

On a clean Debian/Ubuntu machine, install the matching `.deb` with `sudo apt install
./boltwarden_*.deb`. On Arch/Arch Linux ARM, use `sudo pacman -U ./boltwarden-*.pkg.tar.zst`.
Package installation installs the user unit but does not start the app or ask root
which user's session to modify. As the desktop user, run `boltwarden-setup` to get
an explicit yes/no prompt for graphical-login autostart. For automated opt-in use
`boltwarden-setup --enable-service`. Do not run it through sudo.

The user service follows `graphical-session.target`. The desktop/compositor must
start that target and import display variables into the user manager. Check
`systemctl --user status graphical-session.target` and `systemctl --user show-environment`
if the service cannot open its UI. No linger or system-wide daemon is configured.
Disable with `systemctl --user disable --now boltwarden.service` before removing
a package. Package upgrades do not restart an unlocked running vault automatically;
restart it deliberately after saving any edits.

Before publishing, test installation, upgrade, removal, service opt-in/decline,
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
the security, extension, and both architecture checks. Inspect a successful workflow
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
