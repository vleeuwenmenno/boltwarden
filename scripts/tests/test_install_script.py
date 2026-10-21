import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'install.sh'


class InstallScriptTests(unittest.TestCase):
    """Exercise the operating-system dispatch with shims, so both branches run anywhere."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.shims = self.root / 'shims'
        self.shims.mkdir()
        self.log = self.root / 'calls.log'
        self.running = self.root / 'running'
        self.app_directory = self.root / 'Applications'

    def shim(self, name, text='#!/bin/sh\nexit 0\n'):
        path = self.shims / name
        path.write_text(text, encoding='utf-8')
        path.chmod(0o755)

    def run_script(self, *arguments):
        environment = {**os.environ, 'PATH': f'{self.shims}:/usr/bin:/bin'}
        return subprocess.run(
            ['sh', str(SCRIPT), *arguments],
            capture_output=True,
            text=True,
            env=environment,
        )

    def macos(self):
        self.shim('uname', '#!/bin/sh\necho Darwin\n')
        self.shim('codesign')
        self.shim('xattr')
        self.shim('shasum')
        self.shim('open', f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{self.log}"\n')
        # Extract a stand-in bundle for -x and copy it verbatim otherwise.
        self.shim('ditto', '''#!/bin/sh
if [ "$1" = "-x" ]; then
    destination="$4"
    mkdir -p "$destination/Boltwarden.app/Contents/MacOS"
    printf '#!/bin/sh\\nexit 0\\n' > "$destination/Boltwarden.app/Contents/MacOS/boltwarden"
    chmod 0755 "$destination/Boltwarden.app/Contents/MacOS/boltwarden"
else
    cp -R "$1" "$2"
fi
''')
        self.shim('pgrep', f'''#!/bin/sh
if [ -f "{self.running}" ]; then
    echo 4242
else
    exit 1
fi
''')
        self.shim('ps', '#!/bin/sh\nprintf "%s\\n" "boltwarden --daemon"\n')

    def archive(self, name='boltwarden-1.0.0-universal-macos.zip'):
        path = self.root / name
        path.write_text('fixture archive', encoding='utf-8')
        return path

    def source_binary(self):
        path = self.root / 'boltwarden'
        path.write_text('#!/bin/sh\necho fixture\n', encoding='utf-8')
        path.chmod(0o755)
        return path

    def test_linux_install_keeps_installing_the_binary(self):
        self.shim('uname', '#!/bin/sh\necho Linux\n')
        destination = self.root / 'bin' / 'boltwarden'
        result = self.run_script(
            'install', str(self.source_binary()), str(destination),
            str(self.root / 'missing.zip'), str(self.app_directory),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(destination.read_text(encoding='utf-8'), '#!/bin/sh\necho fixture\n')
        self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
        self.assertIn(f'installed {destination}', result.stdout)
        self.assertFalse(self.app_directory.exists())

    def test_linux_uninstall_keeps_removing_the_binary(self):
        self.shim('uname', '#!/bin/sh\necho Linux\n')
        destination = self.root / 'bin' / 'boltwarden'
        destination.parent.mkdir()
        destination.write_text('fixture', encoding='utf-8')
        result = self.run_script('uninstall', str(destination), str(self.app_directory))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(destination.exists())
        self.assertIn(f'removed {destination}', result.stdout)

    def test_install_binary_still_skips_detection(self):
        self.macos()
        destination = self.root / 'bin' / 'boltwarden'
        result = self.run_script('install-binary', str(self.source_binary()), str(destination))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(destination.is_file())
        self.assertFalse(self.app_directory.exists())

    def test_macos_install_replaces_the_app_bundle(self):
        self.macos()
        archive = self.archive()
        stale = self.app_directory / 'Boltwarden.app' / 'Contents' / 'stale'
        stale.parent.mkdir(parents=True)
        stale.write_text('old', encoding='utf-8')
        result = self.run_script(
            'install', str(self.source_binary()), str(self.root / 'bin' / 'boltwarden'),
            str(archive), str(self.app_directory),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        app = self.app_directory / 'Boltwarden.app'
        self.assertTrue((app / 'Contents/MacOS/boltwarden').is_file())
        self.assertFalse(stale.exists())
        self.assertIn(f'installed {app}', result.stdout)
        self.assertFalse(self.running.exists())
        self.assertFalse(self.log.exists())

    def test_macos_install_requires_the_archive(self):
        self.macos()
        result = self.run_script(
            'install', str(self.source_binary()), str(self.root / 'bin' / 'boltwarden'),
            str(self.root / 'missing.zip'), str(self.app_directory),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('make package-macos', result.stderr)
        self.assertFalse(self.app_directory.exists())

    def test_macos_install_rejects_a_mismatched_checksum(self):
        self.macos()
        archive = self.archive()
        archive.with_name(archive.name + '.sha256').write_text(
            f'{"0" * 64}  {archive.name}\n', encoding='utf-8'
        )
        self.shim('shasum', '#!/bin/sh\nexit 1\n')
        result = self.run_script(
            'install', str(self.source_binary()), str(self.root / 'bin' / 'boltwarden'),
            str(archive), str(self.app_directory),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('checksum does not match', result.stderr)
        self.assertFalse((self.app_directory / 'Boltwarden.app').exists())

    def test_macos_install_restarts_a_running_copy(self):
        self.macos()
        binary = self.app_directory / 'Boltwarden.app' / 'Contents' / 'MacOS' / 'boltwarden'
        binary.parent.mkdir(parents=True)
        binary.write_text(
            f'#!/bin/sh\nif [ "$1" = quit ]; then rm -f "{self.running}"; fi\nexit 0\n',
            encoding='utf-8',
        )
        binary.chmod(0o755)
        self.running.write_text('running', encoding='utf-8')
        result = self.run_script(
            'install', str(self.source_binary()), str(self.root / 'bin' / 'boltwarden'),
            str(self.archive()), str(self.app_directory),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('stopped the running Boltwarden', result.stdout)
        self.assertIn('started Boltwarden', result.stdout)
        self.assertIn('--args --daemon', self.log.read_text(encoding='utf-8'))

    def test_macos_uninstall_removes_the_app(self):
        self.macos()
        app = self.app_directory / 'Boltwarden.app'
        (app / 'Contents' / 'MacOS').mkdir(parents=True)
        result = self.run_script(
            'uninstall', str(self.root / 'bin' / 'boltwarden'), str(self.app_directory),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(app.exists())
        self.assertIn(f'removed {app}', result.stdout)


if __name__ == '__main__':
    unittest.main()
