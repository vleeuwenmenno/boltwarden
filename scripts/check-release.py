#!/usr/bin/env python3
"""Fail tag builds before publishing mismatched or incomplete release metadata."""
import json
import os
from pathlib import Path
import tomllib
from release_versions import package_versions

root = Path(__file__).resolve().parents[1]
package = tomllib.loads((root / 'Cargo.toml').read_text())['package']
tag = os.environ['RELEASE_TAG']
package_versions(package['version'])
if tag != f"v{package['version']}":
    raise SystemExit('Release tag must equal v + Cargo.toml package.version')
license_text = (root / 'LICENSE').read_bytes()
if license_text != (root / 'extension/public/LICENSE').read_bytes():
    raise SystemExit('Desktop and extension license notices differ')
version = json.loads((root / 'extension/package.json').read_text())['version']
print(f'Desktop {tag}; extension {version}; licenses match')

notes = root / 'docs' / f"release-notes-{package['version']}.md"
if not notes.is_file():
    raise SystemExit(f'Missing release notes: {notes.name}')
