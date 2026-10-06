from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from importlib.machinery import SourceFileLoader
classify = SourceFileLoader('ci_changes', str(Path(__file__).resolve().parents[1] / 'ci-changes.py')).load_module().classify


class CiChangesTests(unittest.TestCase):
    def test_routing(self):
        cases = [
            (['src/vault.rs'], (True, False, False)),
            (['extension/entrypoints/content.ts'], (False, True, False)),
            (['extension/protocol/fixtures/list-matches.json'], (True, True, False)),
            (['extension/lib/browser-identities.json'], (True, True, False)),
            (['extension/lib/other.ts'], (False, True, False)),
            (['docs/releasing.md', 'README.md'], (False, False, False)),
            (['.github/workflows/ci.yml'], (True, True, True)),
            (['LICENSE'], (True, True, True)),
            (['extension/package.json', 'Cargo.lock'], (True, True, False)),
            (['docs/screenshots/a.png', 'docs/badges/b.svg'], (False, False, False)),
            (['website/src/pages/index.astro', 'website/Dockerfile'], (False, False, True)),
            (['PRIVACY.md', 'SECURITY.md'], (False, False, False)),
            (['docs/releasing.md', 'src/main.rs'], (True, False, False)),
            (['website/src/a.astro', 'src/main.rs'], (True, False, True)),
            ([], (False, False, False)),
        ]
        for paths, expected in cases:
            with self.subTest(paths=paths):
                self.assertEqual(classify(paths), expected)


if __name__ == '__main__':
    unittest.main()
