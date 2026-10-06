#!/usr/bin/env python3
"""Stamp the version named by RELEASE_TAG into this checkout before a release build.

Release versions come from tags; the change is never committed.
"""
import os
from pathlib import Path
from release_versions import set_version, tag_version

root = Path(__file__).resolve().parents[1]
version = tag_version(os.environ['RELEASE_TAG'])
set_version(root, version)
print(f'Building Boltwarden {version}')
