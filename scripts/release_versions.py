"""Map supported release versions to package-manager ordering conventions."""
import re


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
    debian, arch = package_versions(version)
    names = [f'boltwarden-{version}-{cpu}-linux.tar.gz' for cpu in ('x86_64', 'aarch64')]
    names += [f'boltwarden-{arch}-1-{cpu}.pkg.tar.zst' for cpu in ('x86_64', 'aarch64')]
    names += [f'boltwarden_{debian}_{cpu}.deb' for cpu in ('amd64', 'arm64')]
    names += [f'boltwarden-browser-{extension_version}-{browser}.zip' for browser in ('chrome', 'firefox', 'sources')]
    return names
