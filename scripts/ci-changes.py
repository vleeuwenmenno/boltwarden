#!/usr/bin/env python3
"""Decide which CI job groups a change needs, to save runner minutes.

Prints `desktop=true|false` and `extension=true|false` lines for $GITHUB_OUTPUT.
Usage: ci-changes.py [BASE_SHA]. Without a usable base, everything runs.
"""
import re
import subprocess
import sys

# Extension files the desktop build embeds (see packaging/Dockerfile).
DESKTOP_SHARED = re.compile(r'extension/(public/|protocol/|lib/browser-identities\.json$)')
# Files that only affect the extension build.
EXTENSION_ONLY = re.compile(r'extension/|packaging/Dockerfile\.extension$|scripts/third-party-notices\.py$')
DOCS_ONLY = re.compile(r'docs/|[^/]+\.md$')
EVERYTHING = re.compile(r'\.github/|LICENSE$')


def classify(paths):
    desktop = extension = False
    for path in paths:
        if EVERYTHING.match(path):
            return True, True
        if DOCS_ONLY.match(path):
            continue
        if EXTENSION_ONLY.match(path):
            extension = True
            desktop = desktop or bool(DESKTOP_SHARED.match(path))
        else:
            desktop = True
    return desktop, extension


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else ''
    desktop = extension = True
    if base and not set(base) <= {'0'}:
        diff = subprocess.run(['git', 'diff', '--name-only', base, 'HEAD'], capture_output=True, text=True)
        if diff.returncode == 0:
            desktop, extension = classify(diff.stdout.split())
    print(f'desktop={str(desktop).lower()}')
    print(f'extension={str(extension).lower()}')


if __name__ == '__main__':
    main()
