import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('macos_package', ROOT / 'scripts/package-macos.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class MacosPackagingTests(unittest.TestCase):
    def test_info_plist_versions_and_menu_bar_app(self):
        plist = package.info_plist('1.2.3')
        self.assertEqual(plist['CFBundleShortVersionString'], '1.2.3')
        self.assertEqual(plist['CFBundleVersion'], '1.2.3')
        self.assertEqual(plist['CFBundleIdentifier'], 'nl.mvl.boltwarden')
        self.assertEqual(plist['CFBundleExecutable'], 'boltwarden')
        self.assertTrue(plist['LSUIElement'])
        candidate = package.info_plist('1.2.3-rc.4')
        self.assertEqual(candidate['CFBundleShortVersionString'], '1.2.3')
        self.assertEqual(candidate['CFBundleVersion'], '1.2.3-rc.4')
        with self.assertRaises(ValueError):
            package.info_plist('1.2')

    def test_rejects_missing_executables(self):
        with tempfile.TemporaryDirectory() as temporary:
            binaries = Path(temporary) / 'release'
            binaries.mkdir()
            (binaries / 'boltwarden').write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'Missing or empty executable'):
                package.build_app([binaries], Path(temporary) / 'icon.iconset',
                                  Path(temporary) / 'Boltwarden.app', '1.2.3')


if __name__ == '__main__':
    unittest.main()
