#!/usr/bin/env python3
"""Package a distro-built Linux ELF binary; never execute the supplied binary."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tempfile
import tomllib
from release_versions import package_versions

ROOT = Path(__file__).resolve().parents[1]
ARCHES = {62: ('x86_64', 'amd64'), 183: ('aarch64', 'arm64')}


def architecture(binary):
    with binary.open('rb') as stream:
        header = stream.read(20)
    if len(header) < 20 or header[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Expected a 64-bit little-endian Linux ELF binary')
    machine = struct.unpack_from('<H', header, 18)[0]
    if machine not in ARCHES:
        raise ValueError(f'Unsupported ELF architecture: {machine}')
    return ARCHES[machine]


def install(source, destination, mode=0o644):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def archive(root, destination, epoch, prefix=''):
    with tarfile.open(destination, 'w') as output:
        for path in sorted(root.rglob('*')):
            name = str(Path(prefix) / path.relative_to(root))
            info = output.gettarinfo(str(path), arcname=name)
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            info.mtime = epoch
            if path.is_file():
                with path.open('rb') as data:
                    output.addfile(info, data)
            else:
                output.addfile(info)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']['version']
    try:
        deb_version, arch_version = package_versions(version)
    except ValueError as error:
        parser.error(str(error))
    arch, deb_arch = architecture(args.binary)
    # Nix-linked ELF files are not portable distribution binaries.
    dynamic = subprocess.check_output(['readelf', '-l', '-d', str(args.binary)], text=True)
    if '/nix/store/' in dynamic:
        parser.error('Use packaging/Dockerfile; Nix store binaries are not portable packages')
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output.resolve()
    artifacts = []
    with tempfile.TemporaryDirectory(prefix='boltwarden-packaging-') as temporary:
        work = Path(temporary)
        root = work / 'package'
        install(args.binary, root / 'usr/bin/boltwarden', 0o755)
        install(ROOT / 'packaging/boltwarden-setup', root / 'usr/bin/boltwarden-setup', 0o755)
        install(ROOT / 'packaging/boltwarden.service', root / 'usr/lib/systemd/user/boltwarden.service')
        install(ROOT / 'packaging/boltwarden.desktop', root / 'usr/share/applications/boltwarden.desktop')
        install(ROOT / 'extension/public/bolt.svg', root / 'usr/share/icons/hicolor/scalable/apps/boltwarden.svg')
        install(ROOT / 'README.md', root / 'usr/share/doc/boltwarden/README.md')
        install(ROOT / 'LICENSE', root / 'usr/share/licenses/boltwarden/LICENSE')
        install(ROOT / 'LICENSE', root / 'usr/share/doc/boltwarden/copyright')

        notices = ROOT / 'THIRD_PARTY_NOTICES.txt'
        if notices.is_file():
            install(notices, root / 'usr/share/doc/boltwarden/THIRD_PARTY_NOTICES.txt')

        bundle = work / 'bundle'
        install(args.binary, bundle / 'boltwarden', 0o755)
        install(ROOT / 'README.md', bundle / 'README.md')
        install(ROOT / 'scripts/install.sh', bundle / 'install.sh', 0o755)
        if (ROOT / 'LICENSE').is_file():
            install(ROOT / 'LICENSE', bundle / 'LICENSE')
        if notices.is_file():
            install(notices, bundle / 'THIRD_PARTY_NOTICES.txt')
        name = f'boltwarden-{version}-{arch}-linux'
        tar = work / 'bundle.tar'
        archive(bundle, tar, epoch, name)
        import gzip
        target = output / f'{name}.tar.gz'
        with target.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch) as compressed:
            with tar.open('rb') as data:
                shutil.copyfileobj(data, compressed)
        artifacts.append(target)

        debian = root / 'DEBIAN'
        debian.mkdir()
        size = sum(p.stat().st_size for p in root.rglob('*') if p.is_file()) // 1024 + 1
        (debian / 'control').write_text(f'''Package: boltwarden
Version: {deb_version}
Architecture: {deb_arch}
Maintainer: Menno van Leeuwen <menno@vleeuwen.me>
Section: utils
Priority: optional
Installed-Size: {size}
Depends: libc6 (>= 2.36), libgcc-s1, libfontconfig1, libgl1, libx11-6, libxcursor1, libxi6, libxrandr2, libxcb1, libxkbcommon0, libwayland-client0
Recommends: dbus-user-session
Homepage: https://github.com/vleeuwenmenno/boltwarden
Description: Unofficial Linux desktop client for Bitwarden and Vaultwarden
 Includes browser integration and an optional systemd user service.
 Run boltwarden-setup as your desktop user to enable autostart.
''')
        target = output / f'boltwarden_{version}_{deb_arch}.deb'
        subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(root), str(target)], check=True)
        artifacts.append(target)
        shutil.rmtree(debian)

        license_id = tomllib.loads((ROOT / 'Cargo.toml').read_text())['package'].get('license', 'LicenseRef-MIT-Commons-Clause')
        (root / '.PKGINFO').write_text(f'''pkgname = boltwarden
pkgbase = boltwarden
pkgver = {arch_version}-1
pkgdesc = Unofficial Linux desktop client for Bitwarden and Vaultwarden
url = https://github.com/vleeuwenmenno/boltwarden
builddate = {epoch}
packager = Boltwarden maintainers
size = {size * 1024}
arch = {arch}
license = {license_id}
depend = glibc>=2.36
depend = gcc-libs
depend = fontconfig
depend = libglvnd
depend = libx11
depend = libxcursor
depend = libxi
depend = libxrandr
depend = libxcb
depend = libxkbcommon
depend = wayland
optdepend = systemd: optional user service
''')
        (root / '.INSTALL').write_text('post_install() { echo "Run boltwarden-setup as your desktop user to configure autostart."; }\n')
        tar = work / 'arch.tar'
        archive(root, tar, epoch)
        target = output / f'boltwarden-{arch_version}-1-{arch}.pkg.tar.zst'
        subprocess.run(['zstd', '-q', '-f', str(tar), '-o', str(target)], check=True)
        artifacts.append(target)
    for artifact in artifacts:
        digest = hashlib.file_digest(artifact.open('rb'), 'sha256').hexdigest()
        artifact.with_name(artifact.name + '.sha256').write_text(f'{digest}  {artifact.name}\n')
        print(artifact)


if __name__ == '__main__':
    main()
