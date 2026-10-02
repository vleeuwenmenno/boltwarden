#!/usr/bin/env python3
"""Verify the exact release inventory and each checksum before uploading."""
import hashlib
import json
import sys
import tomllib
from pathlib import Path
from release_versions import artifact_names

root = Path(__file__).resolve().parents[1]
version = tomllib.loads((root / 'Cargo.toml').read_text())['package']['version']
extension = json.loads((root / 'extension/package.json').read_text())['version']
directory = Path(sys.argv[1])
names = artifact_names(version, extension)
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
