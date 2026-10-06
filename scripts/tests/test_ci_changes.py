from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from importlib.machinery import SourceFileLoader
classify = SourceFileLoader('ci_changes', str(Path(__file__).resolve().parents[1] / 'ci-changes.py')).load_module().classify


class CiChangesTests(unittest.TestCase):
    def test_routing(self):
        cases = [
            (['src/vault.rs'], (True, False)),
            (['extension/entrypoints/content.ts'], (False, True)),
            (['extension/protocol/fixtures/list-matches.json'], (True, True)),
            (['extension/lib/browser-identities.json'], (True, True)),
            (['extension/lib/other.ts'], (False, True)),
            (['docs/releasing.md', 'README.md'], (False, False)),
            (['.github/workflows/ci.yml'], (True, True)),
            (['LICENSE'], (True, True)),
            (['extension/package.json', 'Cargo.lock'], (True, True)),
            (['docs/screenshots/a.png', 'docs/badges/b.svg'], (False, False)),
            (['PRIVACY.md', 'SECURITY.md'], (False, False)),
            (['docs/releasing.md', 'src/main.rs'], (True, False)),
            ([], (False, False)),
        ]
        for paths, expected in cases:
            with self.subTest(paths=paths):
                self.assertEqual(classify(paths), expected)


if __name__ == '__main__':
    unittest.main()
