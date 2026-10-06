# Repository instructions

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
   browser checks, builds native x86_64 and ARM64 Linux packages plus the Windows
   x64 installer/ZIP, and creates a draft release. RC tags are marked as prereleases.
   Expected attachments are ten
   artifacts plus their ten SHA-256 checksum files: tarballs, Debian packages,
   Arch packages, and Fedora RPMs for both CPUs, and the Windows installer and ZIP.
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
