#!/usr/bin/env python3
"""Verify the exact release inventory and each checksum before uploading.

Usage: check-release-artifacts.py [--extension] DIRECTORY
Desktop tags (v*) and extension tags (extension-v*) publish separate inventories.
"""
import hashlib
import json
import sys
import tomllib
from pathlib import Path
from release_versions import desktop_artifact_names, extension_artifact_names

root = Path(__file__).resolve().parents[1]
args = sys.argv[1:]
extension_release = args[0] == '--extension'
directory = Path(args[-1])
if extension_release:
    version = json.loads((root / 'extension/package.json').read_text())['version']
    names = extension_artifact_names(version)
else:
    version = tomllib.loads((root / 'Cargo.toml').read_text())['package']['version']
    names = desktop_artifact_names(version)
expected = set(names) | {name + '.sha256' for name in names}
actual = {path.name for path in directory.iterdir()}
if actual != expected:
    raise SystemExit(f'Release inventory mismatch: missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}')
for name in names:
    path = directory / name
    if not path.is_file() or path.stat().st_size == 0:
        raise SystemExit(f'Empty or non-file artifact: {name}')
    digest = hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()
    if (directory / (name + '.sha256')).read_text().strip() != f'{digest}  {name}':
        raise SystemExit(f'Invalid checksum: {name}')
print(f'Validated {len(names)} artifacts and their checksums for {version}')
