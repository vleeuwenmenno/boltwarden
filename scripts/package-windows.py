#!/usr/bin/env python3
"""Package the two native Windows executables; do not execute build inputs."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import tomllib
import zipfile
from release_versions import package_versions

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = ('boltwarden.exe', 'boltwarden-native-host.exe', 'LICENSE',
           'THIRD_PARTY_NOTICES.txt', 'WINDOWS.txt')


def inspect_pe(path):
    data = path.read_bytes()
    if len(data) < 64 or data[:2] != b'MZ':
        raise ValueError('Expected a Windows PE executable')
    offset = struct.unpack_from('<I', data, 60)[0]
    if offset + 24 > len(data) or data[offset:offset + 4] != b'PE\0\0':
        raise ValueError('Invalid PE signature')
    machine, sections = struct.unpack_from('<HH', data, offset + 4)
    optional_size = struct.unpack_from('<H', data, offset + 20)[0]
    optional = offset + 24
    if machine != 0x8664 or optional_size < 128 or optional + optional_size > len(data):
        raise ValueError('Expected an x86_64 Windows executable')
    if struct.unpack_from('<H', data, optional)[0] != 0x20b:
        raise ValueError('Expected PE32+ optional header')
    table = optional + optional_size

    def rva(address):
        for index in range(sections):
            start = table + index * 40
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from('<IIII', data, start + 8)
            if virtual_address <= address < virtual_address + max(virtual_size, raw_size):
                result = raw_offset + address - virtual_address
                if result >= len(data):
                    raise ValueError('PE address outside file')
                return result
        raise ValueError('Unmapped PE address')

    imports = []
    address = struct.unpack_from('<I', data, optional + 120)[0]
    if address:
        cursor = rva(address)
        for _ in range(256):
            descriptor = struct.unpack_from('<IIIII', data, cursor)
            if not any(descriptor):
                break
            start = rva(descriptor[3])
            end = data.index(b'\0', start, min(start + 256, len(data)))
            imports.append(data[start:end].decode('ascii').lower())
            cursor += 20
        else:
            raise ValueError('Too many DLL imports')
    return imports


def validate_runtime(path):
    imports = inspect_pe(path)
    for name in imports:
        if name != Path(name).name or '/' in name or '\\' in name:
            raise ValueError(f'Invalid DLL import: {name}')
        if name.startswith(('vcruntime', 'msvcp', 'libgcc', 'libstdc++', 'libwinpthread')):
            raise ValueError(f'Non-system runtime dependency: {name}; build with static CRT')
        if os.name == 'nt' and not name.startswith(('api-ms-', 'ext-ms-')):
            if not (Path(os.environ['SystemRoot']) / 'System32' / name).is_file():
                raise ValueError(f'DLL is not available from Windows: {name}')
    return imports


def checksum(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    path.with_name(path.name + '.sha256').write_text(f'{digest}  {path.name}\n', encoding='utf-8', newline='\n')


def create_zip(payload, destination, epoch):
    stamp = time.gmtime(max(315532800, min(epoch, 4354819198)))[:6]
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in PAYLOAD:
            info = zipfile.ZipInfo(name, stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, (payload / name).read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary-dir', type=Path, required=True)
    parser.add_argument('--iscc', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text(encoding='utf-8'))['package']['version']
    package_versions(version)
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output.resolve()
    with tempfile.TemporaryDirectory(prefix='boltwarden-windows-package-') as temporary:
        payload = Path(temporary)
        for name in PAYLOAD:
            source = args.binary_dir / name if name.endswith('.exe') else (
                ROOT / 'packaging/windows/WINDOWS.txt' if name == 'WINDOWS.txt' else ROOT / name)
            if not source.is_file() or source.stat().st_size == 0:
                raise ValueError(f'Missing or empty payload: {source}')
            if name.endswith('.exe'):
                print(f'{name} imports: {", ".join(validate_runtime(source))}')
            shutil.copyfile(source, payload / name)
        archive = output / f'boltwarden-{version}-x86_64-windows.zip'
        create_zip(payload, archive, int(os.environ.get('SOURCE_DATE_EPOCH', '0')))
        subprocess.run([str(args.iscc), f'/DVersion={version}', f'/DPayloadDir={payload}',
                        f'/DOutputDir={output}', str(ROOT / 'packaging/windows/boltwarden.iss')], check=True)
        installer = output / f'boltwarden-{version}-x86_64-windows-setup.exe'
        if not installer.is_file() or installer.stat().st_size == 0:
            raise ValueError('Installer compiler produced no setup executable')
        for artifact in (archive, installer):
            checksum(artifact)


if __name__ == '__main__':
    main()
