import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('windows_package', ROOT / 'scripts/package-windows.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class WindowsPackagingTests(unittest.TestCase):
    def test_rejects_elf_truncated_pe_and_wrong_architecture(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'test.exe'
            for body in (b'\x7fELF' + bytes(100), b'MZ', b'MZ' + bytes(62)):
                path.write_bytes(body)
                with self.assertRaises((ValueError, struct.error)):
                    package.inspect_pe(path)
            body = bytearray(512)
            body[:2] = b'MZ'
            struct.pack_into('<I', body, 60, 64)
            body[64:68] = b'PE\0\0'
            struct.pack_into('<HH', body, 68, 0x8664, 0)
            struct.pack_into('<H', body, 84, 240)
            struct.pack_into('<H', body, 88, 0x20b)
            path.write_bytes(body)
            self.assertEqual(package.inspect_pe(path), [])
            struct.pack_into('<H', body, 68, 0xAA64)
            path.write_bytes(body)
            with self.assertRaises(ValueError):
                package.inspect_pe(path)

    def test_zip_has_exact_payload_reproducible_bytes_and_checksum(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in package.PAYLOAD:
                (root / name).write_bytes(name.encode('utf-8'))
            first, second = root / 'first.zip', root / 'second.zip'
            package.create_zip(root, first, 1750000000)
            package.create_zip(root, second, 1750000000)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(set(archive.namelist()), set(package.PAYLOAD))
                self.assertIsNone(archive.testzip())
            package.checksum(first)
            self.assertRegex((root / 'first.zip.sha256').read_text(), r'^[a-f0-9]{64}  first.zip\n$')
