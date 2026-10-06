"""Map supported release versions to package-manager ordering conventions."""
import re
from pathlib import Path


def package_versions(version):
    number = r'(?:0|[1-9][0-9]*)'
    match = re.fullmatch(rf'({number}\.{number}\.{number})(?:-rc\.([1-9][0-9]*))?', version)
    if not match:
        raise ValueError('Expected X.Y.Z or X.Y.Z-rc.N (N starts at 1)')
    stable, candidate = match.groups()
    if candidate:
        return f'{stable}~rc.{candidate}', f'{stable}rc{candidate}'
    return stable, stable


def artifact_names(version, extension_version):
    _, arch = package_versions(version)
    names = [f'boltwarden-{version}-{cpu}-linux.tar.gz' for cpu in ('x86_64', 'aarch64')]
    names += [f'boltwarden-{arch}-1-{cpu}.pkg.tar.zst' for cpu in ('x86_64', 'aarch64')]
    # Keep '~' inside Debian metadata only: GitHub rewrites it in asset names.
    names += [f'boltwarden_{version}_{cpu}.deb' for cpu in ('amd64', 'arm64')]
    names += [f'boltwarden-{version}-1.{cpu}.rpm' for cpu in ('x86_64', 'aarch64')]
    names += [f'boltwarden-browser-{extension_version}-{browser}.zip' for browser in ('chrome', 'firefox', 'sources')]
    names += [f'boltwarden-{version}-x86_64-windows.zip', f'boltwarden-{version}-x86_64-windows-setup.exe']
    return names


def tag_version(tag):
    """The desktop version a release tag names, such as 1.0.0-rc.3 for v1.0.0-rc.3."""
    if not tag.startswith('v'):
        raise ValueError(f'Release tag must start with v: {tag}')
    version = tag[1:]
    package_versions(version)
    return version


def set_version(root, version):
    """Stamp the desktop version into Cargo.toml and Cargo.lock of a build checkout."""
    package_versions(version)
    root = Path(root)
    manifest = root / 'Cargo.toml'
    text, count = re.subn(
        r'(\[package\][^\[]*?^version = )"[^"]*"',
        rf'\1"{version}"',
        manifest.read_text(encoding='utf-8'),
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise ValueError('Cargo.toml has no [package] version')
    manifest.write_text(text, encoding='utf-8')
    lock = root / 'Cargo.lock'
    text, count = re.subn(
        r'(\[\[package\]\]\nname = "boltwarden"\nversion = )"[^"]*"',
        rf'\1"{version}"',
        lock.read_text(encoding='utf-8'),
        count=1,
    )
    if count != 1:
        raise ValueError('Cargo.lock has no boltwarden package entry')
    lock.write_text(text, encoding='utf-8')
