#!/usr/bin/env python3
"""Fail tag builds before publishing mismatched or incomplete release metadata.

Desktop tags are v + Cargo.toml version. Extension tags are extension-v + the
extension/package.json version and release independently of the desktop app.
"""
import json
import os
from pathlib import Path
import re
import tomllib
from release_versions import package_versions

root = Path(__file__).resolve().parents[1]
tag = os.environ['RELEASE_TAG']
if (root / 'LICENSE').read_bytes() != (root / 'extension/public/LICENSE').read_bytes():
    raise SystemExit('Desktop and extension license notices differ')

if tag.startswith('extension-v'):
    version = json.loads((root / 'extension/package.json').read_text())['version']
    if not re.fullmatch(r'(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}', version):
        raise SystemExit('Extension version must be numeric X.Y.Z (browser manifest rule)')
    if tag != f'extension-v{version}':
        raise SystemExit('Extension tag must equal extension-v + extension/package.json version')
    print(f'Extension {tag}; licenses match')
else:
    package = tomllib.loads((root / 'Cargo.toml').read_text())['package']
    package_versions(package['version'])
    if tag != f"v{package['version']}":
        raise SystemExit('Release tag must equal v + Cargo.toml package.version')
    notes = root / 'docs' / f"release-notes-{package['version']}.md"
    if not notes.is_file():
        raise SystemExit(f'Missing release notes: {notes.name}')
    print(f'Desktop {tag}; licenses match')
