import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('third_party_notices', ROOT / 'scripts/third-party-notices.py')
notices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notices)


class NoticeTests(unittest.TestCase):
    def test_collects_bundled_font_licenses_alongside_package_notices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = ['LICENSE-MIT', 'licenses/NOTICE', 'fonts/Hack-Regular.txt',
                        'fonts/OFL.txt', 'fonts/UFL.txt', 'fonts/emoji-icon-font-mit-license.txt']
            for relative in expected + ['README.md', 'fonts/Hack-Regular.ttf']:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture')
            self.assertEqual(set(expected), {
                str(path.relative_to(root)) for path in notices.license_files(root)
            })


if __name__ == '__main__':
    unittest.main()
