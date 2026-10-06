#!/usr/bin/env python3
"""Bundle the macOS executables into Boltwarden.app and zip it; do not execute build inputs.

Pass --binary-dir once per CPU (for example the aarch64 and x86_64 release folders);
two folders are merged into universal executables with lipo. The app is signed ad hoc,
since it is distributed without a paid Developer ID.
"""
import argparse
import hashlib
import plistlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
from release_versions import package_versions

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ID = 'nl.mvl.boltwarden'
EXECUTABLES = ('boltwarden', 'boltwarden-native-host')
CPU_NAMES = {'arm64': 'aarch64', 'x86_64': 'x86_64'}
MINIMUM_MACOS = '11.0'


def run(*command):
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def architectures(path):
    """CPU architectures of a Mach-O file, read by lipo rather than by running it."""
    try:
        return sorted(run('lipo', '-archs', str(path)).split())
    except subprocess.CalledProcessError as error:
        raise ValueError(f'Not a macOS executable: {path}: {error.stderr.strip()}') from error


def info_plist(version):
    stable, _ = package_versions(version)
    return {
        'CFBundleDevelopmentRegion': 'en',
        'CFBundleDisplayName': 'Boltwarden',
        'CFBundleExecutable': 'boltwarden',
        'CFBundleIconFile': 'Boltwarden',
        'CFBundleIdentifier': BUNDLE_ID,
        'CFBundleInfoDictionaryVersion': '6.0',
        'CFBundleName': 'Boltwarden',
        'CFBundlePackageType': 'APPL',
        # Finder shows the short version; release candidates keep their suffix in the build.
        'CFBundleShortVersionString': stable.split('~')[0],
        'CFBundleVersion': version,
        'LSApplicationCategoryType': 'public.app-category.utilities',
        'LSMinimumSystemVersion': MINIMUM_MACOS,
        # A menu bar app: no Dock icon until the vault window opens.
        'LSUIElement': True,
        'NSHighResolutionCapable': True,
    }


def checksum(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    path.with_name(path.name + '.sha256').write_text(f'{digest}  {path.name}\n', encoding='utf-8')


def build_app(binary_dirs, iconset, destination, version):
    contents = destination / 'Contents'
    macos = contents / 'MacOS'
    resources = contents / 'Resources'
    macos.mkdir(parents=True)
    resources.mkdir()
    cpus = set()
    for name in EXECUTABLES:
        sources = [directory / name for directory in binary_dirs]
        for source in sources:
            if not source.is_file() or source.stat().st_size == 0:
                raise ValueError(f'Missing or empty executable: {source}')
        target = macos / name
        if len(sources) == 1:
            shutil.copyfile(sources[0], target)
        else:
            run('lipo', '-create', '-output', str(target), *map(str, sources))
        target.chmod(0o755)
        archs = architectures(target)
        if not set(archs) <= set(CPU_NAMES) or (cpus and set(archs) != cpus):
            raise ValueError(f'Unexpected architectures for {name}: {archs}')
        cpus = set(archs)
    with (contents / 'Info.plist').open('wb') as stream:
        plistlib.dump(info_plist(version), stream)
    (contents / 'PkgInfo').write_text('APPL????', encoding='ascii')
    run('iconutil', '-c', 'icns', str(iconset), '-o', str(resources / 'Boltwarden.icns'))
    for name in ('LICENSE', 'THIRD_PARTY_NOTICES.txt'):
        source = ROOT / name
        if not source.is_file() or source.stat().st_size == 0:
            raise ValueError(f'Missing or empty payload: {source}')
        shutil.copyfile(source, resources / name)
    # Sign the helper first; signing the bundle seals the main executable and resources.
    run('codesign', '--force', '--sign', '-', str(macos / 'boltwarden-native-host'))
    run('codesign', '--force', '--sign', '-', str(destination))
    run('codesign', '--verify', '--strict', '--deep', str(destination))
    return sorted(cpus)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary-dir', type=Path, action='append', required=True)
    parser.add_argument('--iconset', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text(encoding='utf-8'))['package']['version']
    package_versions(version)
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='boltwarden-macos-package-') as temporary:
        app = Path(temporary) / 'Boltwarden.app'
        cpus = build_app(args.binary_dir, args.iconset, app, version)
        label = 'universal' if len(cpus) > 1 else CPU_NAMES[cpus[0]]
        archive = args.output.resolve() / f'boltwarden-{version}-{label}-macos.zip'
        archive.unlink(missing_ok=True)
        # ditto keeps the bundle's symlinks and signature intact, unlike plain zip.
        run('ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(app), str(archive))
        checksum(archive)
        print(archive)


if __name__ == '__main__':
    main()
