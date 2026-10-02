import importlib.util
import os
from pathlib import Path
import struct
import sys
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('package_release', ROOT / 'scripts/package-release.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackagingTests(unittest.TestCase):
    def test_architecture_comes_from_binary_not_build_machine(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'boltwarden'
            for machine, expected in [(62, ('x86_64', 'amd64')), (183, ('aarch64', 'arm64'))]:
                header = bytearray(20)
                header[:6] = b'\x7fELF\x02\x01'
                struct.pack_into('<H', header, 18, machine)
                binary.write_bytes(header)
                self.assertEqual(package.architecture(binary), expected)
            for invalid in [b'#!/bin/sh\n', b'\x7fELF\x01\x01' + bytes(14), bytes(20)]:
                binary.write_bytes(invalid)
                with self.assertRaises(ValueError):
                    package.architecture(binary)

    def test_archives_preserve_executable_modes_and_normalize_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'root'
            root.mkdir()
            binary = root / 'boltwarden'
            binary.write_text('fixture')
            binary.chmod(0o755)
            target = Path(directory) / 'artifact.tar'
            package.archive(root, target, 123, 'release')
            with tarfile.open(target) as archive:
                member = archive.getmember('release/boltwarden')
                self.assertEqual((member.uid, member.gid, member.mtime, member.mode), (0, 0, 123, 0o755))
                self.assertEqual(archive.extractfile(member).read(), b'fixture')

    def test_setup_requires_opt_in_and_uses_only_user_systemd(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            log = directory / 'calls'
            for name, script in {
                'id': '#!/bin/sh\necho 1000\n',
                'systemctl': '#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_SYSTEMCTL_LOG"\n',
            }.items():
                path = directory / name
                path.write_text(script)
                path.chmod(0o755)
            env = {**os.environ, 'PATH': f'{directory}:/usr/bin:/bin', 'TEST_SYSTEMCTL_LOG': str(log)}
            script = str(ROOT / 'packaging/boltwarden-setup')
            refused = subprocess.run([script], input='', text=True, env=env, capture_output=True)
            self.assertEqual(refused.returncode, 2)
            self.assertFalse(log.exists())
            subprocess.run([script, '--enable-service'], env=env, check=True, capture_output=True)
            self.assertEqual(log.read_text().splitlines(), [
                '--user daemon-reload', '--user enable --now boltwarden.service'])


if __name__ == '__main__':
    unittest.main()
