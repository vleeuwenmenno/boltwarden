#!/usr/bin/env python3
"""Check the packaged macOS ZIP the way a user receives it.

Usage: macos-smoke.py DIST_DIRECTORY
Extracts the universal ZIP with ditto, verifies its ad hoc signature strictly, checks
both CPU architectures and the bundle metadata, and runs the app's --version.
"""
import hashlib
import plistlib
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
EXECUTABLES = ('boltwarden', 'boltwarden-native-host')


def run(*command):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f'{command[0]} failed: {result.stderr.strip() or result.returncode}')
    return result.stdout


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text(encoding='utf-8'))['package']['version']
    archive = Path(sys.argv[1]) / f'boltwarden-{version}-universal-macos.zip'
    digest = hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()
    checksum = archive.with_name(archive.name + '.sha256').read_text(encoding='utf-8').strip()
    if checksum != f'{digest}  {archive.name}':
        raise SystemExit(f'Checksum does not match {archive.name}')
    with tempfile.TemporaryDirectory(prefix='boltwarden-macos-smoke-') as temporary:
        run('ditto', '-x', '-k', str(archive), temporary)
        app = Path(temporary) / 'Boltwarden.app'
        run('codesign', '--verify', '--strict', '--deep', str(app))
        for name in EXECUTABLES:
            archs = set(run('lipo', '-archs', str(app / 'Contents/MacOS' / name)).split())
            if archs != {'arm64', 'x86_64'}:
                raise SystemExit(f'{name} is not universal: {sorted(archs)}')
        with (app / 'Contents/Info.plist').open('rb') as stream:
            info = plistlib.load(stream)
        if info.get('CFBundleVersion') != version or info.get('CFBundleExecutable') != 'boltwarden':
            raise SystemExit(f'Unexpected Info.plist: {info}')
        if not (app / 'Contents/Resources/Boltwarden.icns').is_file():
            raise SystemExit('The app icon is missing')
        reported = run(str(app / 'Contents/MacOS/boltwarden'), '--version')
        if version not in reported:
            raise SystemExit(f'--version reported {reported!r}, expected {version}')
    print(f'Smoke-tested {archive.name}')


if __name__ == '__main__':
    main()
