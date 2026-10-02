import hashlib
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from release_versions import artifact_names, package_versions


class ReleaseVersionsTests(unittest.TestCase):
    def test_release_names_use_only_github_safe_characters(self):
        names = artifact_names('1.0.0-rc.1', '0.5.6')
        self.assertIn('boltwarden_1.0.0-rc.1_amd64.deb', names)
        self.assertIn('boltwarden_1.0.0-rc.1_arm64.deb', names)
        self.assertIn('boltwarden-1.0.0-rc.1-1.x86_64.rpm', names)
        self.assertIn('boltwarden-1.0.0-rc.1-1.aarch64.rpm', names)
        for name in names:
            self.assertIsNotNone(re.fullmatch(r'[A-Za-z0-9_.-]+', name), name)

    def test_stable_and_rc_package_versions(self):
        self.assertEqual(package_versions('1.0.0'), ('1.0.0', '1.0.0'))
        self.assertEqual(package_versions('1.0.0-rc.1'), ('1.0.0~rc.1', '1.0.0rc1'))
        self.assertEqual(package_versions('2.3.4-rc.12'), ('2.3.4~rc.12', '2.3.4rc12'))
        for value in ['1.0', '01.0.0', '1.0.0-rc.0', '1.0.0-rc.01', '1.0.0-beta.1', '1.0.0+git', '1.0.0\n', '../1.0.0']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                package_versions(value)

    @unittest.skipUnless(shutil.which('vercmp'), 'Arch vercmp not installed')
    def test_arch_upgrades_from_rc_to_final(self):
        versions = ['0.5.0', '1.0.0-rc.1', '1.0.0-rc.2', '1.0.0-rc.10', '1.0.0', '1.0.1-rc.1']
        for old, new in zip(versions, versions[1:]):
            result = subprocess.check_output(['vercmp', package_versions(old)[1], package_versions(new)[1]], text=True)
            self.assertLess(int(result), 0, (old, new))

    @unittest.skipUnless(shutil.which('dpkg'), 'Debian dpkg not installed')
    def test_debian_upgrades_from_rc_to_final(self):
        versions = ['0.5.0', '1.0.0-rc.1', '1.0.0-rc.2', '1.0.0-rc.10', '1.0.0', '1.0.1-rc.1']
        for old, new in zip(versions, versions[1:]):
            subprocess.run(['dpkg', '--compare-versions', package_versions(old)[0], 'lt', package_versions(new)[0]], check=True)

    def test_inventory_rejects_missing_extra_empty_and_corrupt_artifacts(self):
        version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']['version']
        extension = json.loads((ROOT / 'extension/package.json').read_text())['version']
        names = artifact_names(version, extension)
        self.assertEqual(len(names), 13)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in names:
                content = b'synthetic artifact'
                (directory / name).write_bytes(content)
                (directory / (name + '.sha256')).write_text(f'{hashlib.sha256(content).hexdigest()}  {name}\n')
            def check():
                return subprocess.run([sys.executable, str(ROOT / 'scripts/check-release-artifacts.py'), temporary], capture_output=True).returncode
            self.assertEqual(check(), 0)
            first = directory / names[0]
            first.write_bytes(b'corrupted')
            self.assertNotEqual(check(), 0)
            first.write_bytes(b'')
            self.assertNotEqual(check(), 0)
            first.write_bytes(b'synthetic artifact')
            extra = directory / 'unintended.txt'
            extra.write_text('not a release asset')
            self.assertNotEqual(check(), 0)
            extra.unlink()
            first.unlink()
            self.assertNotEqual(check(), 0)
