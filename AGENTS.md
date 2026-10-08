# Repository instructions

## Issues and the project board

Track work in GitHub issues on the **Boltwarden** project board
(GitHub Projects, owner `vleeuwenmenno`). Every feature, bug fix, refactor, and
release starts from an issue. Only trivial changes (typos, comment fixes, routine
dependency bumps) may skip one.

1. Before starting work, find the matching issue or create one. Describe the
   problem or goal, the acceptance criteria, and a task checklist (`- [ ]`).
2. Label each issue with exactly one `type:` label (`type:feature`, `type:bug`,
   `type:chore`, `type:docs`, `type:epic`) and any matching `platform:`
   (`platform:linux`, `platform:windows`, `platform:macos`, `platform:browser`) and
   `area:` labels (`area:auth`, `area:vault`, `area:health`, `area:ui`,
   `area:packaging`). Add `blocked` while an issue waits on something else. Add a `priority:` label (`priority:high`, `priority:medium`,
   `priority:low`) when known.
3. Split large work into an epic with sub-issues. The epic holds the design and
   links each sub-issue; each sub-issue should fit in one pull request.
4. Add every issue to the project board. Move it through the Status column as work
   progresses: **Backlog** (not yet planned), **Ready** (planned and unblocked),
   **In progress**, **In review** (pull request open), **Done**.
5. Branch from `main` per issue, tick off its tasks as they land, and reference it
   in the pull request with `Closes #N` (or `Part of #N` for an epic or partial work).
6. Record design decisions, findings, and changes of plan as issue comments, so the
   issue remains the source of truth.

## Preparing a release

Follow [docs/releasing.md](docs/releasing.md) and the GitHub Actions workflow in
[.github/workflows/ci.yml](.github/workflows/ci.yml). Pushing a release tag starts
the tests and builds; CI creates and populates the GitHub release draft.

1. Merge the changes for the release into `main` through the required CI checks.
   No version bump is needed: tag builds take the desktop version from the tag and
   stamp it into `Cargo.toml` and `Cargo.lock` inside CI only
   (`scripts/set-version.py`). Supported versions are `X.Y.Z` and `X.Y.Z-rc.N`,
   where N starts at 1.
2. Optionally add curated `docs/release-notes-VERSION.md` before tagging. Without
   it, the draft release uses GitHub's generated notes.
3. From the updated `main`, create and push an annotated tag `v` plus the version.
   For example:

   ```sh
   git tag -a v1.0.0-rc.3 -m "Boltwarden 1.0.0-rc.3"
   git push origin v1.0.0-rc.3
   ```

   The example version is illustrative; always use the version being released.
   Never move or reuse an existing release tag, including failed ones.
4. Wait for the tagged workflow to finish successfully. It runs security and
   browser checks, builds native x86_64 and ARM64 Linux packages, the Windows
   x64 installer/ZIP and the universal macOS ZIP, and creates a draft release. RC tags are marked as prereleases.
   Expected attachments are eleven
   artifacts plus their eleven SHA-256 checksum files: tarballs, Debian packages,
   Arch packages, and Fedora RPMs for both CPUs, the Windows installer and ZIP, and
   the universal macOS app ZIP.
   CI verifies downloads after upload.
5. Review the draft, release notes, artifacts, and applicable manual testing before
   publishing. Do not publish the release before CI finishes: the workflow refuses
   to replace assets on an already published release. Do not modify published
   assets to deliver later changes; prepare a new version and tag.

## Browser extension releases

The extension version is independent of the desktop version. When shipping
extension changes, update `extension/package.json` and its lockfile consistently
and follow [extension/PUBLISHING.md](extension/PUBLISHING.md). Push an annotated
`extension-vX.Y.Z` tag (exact `package.json` version, numeric only) from `main`;
CI runs only the extension job and creates a draft release with the Chrome ZIP,
Firefox ZIP and reviewer source ZIP plus checksums. Browser manifest
versions must remain numeric; do not copy a desktop RC suffix into them.

GitHub release ZIPs do not publish extensions to browser stores. Chrome Web Store
submission and Firefox submission/signing remain separate steps. Packaging RPMs
also does not create a DNF/YUM update repository.

## Website

The landing page lives in `website/` (Astro) and is independent of desktop and extension
releases. Its CI job is routed by path in `scripts/ci-changes.py`: it builds the image on
pull requests, and pushes `ghcr.io/vleeuwenmenno/boltwarden-website` from `main`. No tag or
version is involved. The server (dotfiles repo) pulls `:latest`, and download links read
GitHub releases in the browser, so a release never requires a site change. Run it locally
with `cd website && npm run dev`.
