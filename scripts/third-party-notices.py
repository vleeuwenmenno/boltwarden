#!/usr/bin/env python3
"""Collect dependency license texts from the installed, locked build inputs."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def license_files(directory):
    for base in [directory, directory / 'LICENSES', directory / 'licenses']:
        if not base.is_dir():
            continue
        for file in sorted(base.iterdir()):
            if file.is_file() and file.name.lower().startswith(('license', 'licence', 'copying', 'copyright', 'notice')):
                yield file
    # epaint_default_fonts ships the font authors' licenses beside the fonts,
    # including Hack-Regular.txt, OFL.txt, UFL.txt and the emoji font license.
    # Keep these texts even though they do not use a LICENSE filename.
    fonts = directory / 'fonts'
    if fonts.is_dir():
        for file in sorted(fonts.glob('*.txt')):
            if file.is_file():
                yield file


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ecosystem', choices=['rust', 'npm'])
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    entries = []
    if args.ecosystem == 'rust':
        host = next(line.split(': ', 1)[1] for line in subprocess.check_output(['rustc', '-vV'], text=True).splitlines() if line.startswith('host: '))
        metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--format-version=1', '--filter-platform', host], cwd=ROOT))
        for package in metadata['packages']:
            if package['source'] is None:
                continue
            entries.append((package['name'], package['version'], package.get('license'), Path(package['manifest_path']).parent, package.get('repository')))
    else:
        extension = ROOT / 'extension'
        lock = json.loads((extension / 'package-lock.json').read_text())
        for location in lock['packages']:
            if not location:
                continue
            directory = extension / location
            manifest = directory / 'package.json'
            if not manifest.is_file():
                continue  # Optional dependencies for other platforms are not shipped.
            package = json.loads(manifest.read_text())
            entries.append((package['name'], package['version'], package.get('license'), directory, package.get('repository')))
    texts = ['Third-party notices\n\nDependencies retain their own licenses. This collection includes build/test\ndependencies as well as runtime dependencies; inclusion does not imply that\nevery listed dependency is shipped in the executable or extension.\n']
    for name, version, declared, directory, repository in sorted(entries, key=lambda entry: entry[:2]):
        texts.append(f'\n{"=" * 72}\n{name} {version}\nDeclared license: {declared}\nSource: {repository}\n')
        files = list(license_files(directory))
        for file in files:
            texts.append(f'\n--- {file.relative_to(directory)} ---\n{file.read_text(errors="replace")}\n')
        if not files:
            texts.append('\nNo separate license text supplied in this dependency package; consult its source.\n')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(''.join(texts))
    print(f'Collected notices for {len(entries)} {args.ecosystem} dependencies')


if __name__ == '__main__':
    main()
