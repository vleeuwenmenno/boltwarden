# Repository instructions

## Preparing a release

Follow [docs/releasing.md](docs/releasing.md) and the GitHub Actions workflow in
[.github/workflows/ci.yml](.github/workflows/ci.yml). Pushing a release tag starts
the tests and builds; CI creates and populates the GitHub release draft.

1. Update the desktop version in `Cargo.toml` and the Boltwarden package entry in
   `Cargo.lock`. Supported versions are `X.Y.Z` and `X.Y.Z-rc.N`, where N starts at
   1. Avoid unrelated dependency updates during a version bump.
2. Add `docs/release-notes-VERSION.md` for that exact version. Run
   `RELEASE_TAG=vVERSION python3 scripts/check-release.py`, replacing VERSION with
   the new version. Merge the preparation changes into `main` through the required
   CI checks.
3. From the updated `main`, create and push an annotated tag matching `v` plus the
   exact `Cargo.toml` version. For example:

   ```sh
   git tag -a v1.0.0-rc.2 -m "Boltwarden 1.0.0-rc.2"
   git push github v1.0.0-rc.2
   ```

   The example version is illustrative; always use the version being released.
   Never move or reuse an existing release tag.
4. Wait for the tagged workflow to finish successfully. It runs security and
   browser checks, builds native x86_64 and ARM64 Linux packages plus the Windows
   x64 installer/ZIP, and creates a draft release. RC tags are marked as prereleases.
   Expected attachments are thirteen
   artifacts plus their thirteen SHA-256 checksum files: tarballs, Debian packages,
   Arch packages, and Fedora RPMs for both CPUs; separate Chrome and Firefox ZIPs;
   the extension reviewer source ZIP; and the Windows installer and ZIP. CI verifies
   downloads after upload.
5. Review the draft, release notes, artifacts, and applicable manual testing before
   publishing. Do not publish the release before CI finishes: the workflow refuses
   to replace assets on an already published release. Do not modify published
   assets to deliver later changes; prepare a new version and tag.

## Browser extension releases

The extension version is independent of the desktop version. When shipping
extension changes, update `extension/package.json` and its lockfile consistently
and follow [extension/PUBLISHING.md](extension/PUBLISHING.md). Browser manifest
versions must remain numeric; do not copy a desktop RC suffix into them.

GitHub release ZIPs do not publish extensions to browser stores. Chrome Web Store
submission and Firefox submission/signing remain separate steps. Packaging RPMs
also does not create a DNF/YUM update repository.
