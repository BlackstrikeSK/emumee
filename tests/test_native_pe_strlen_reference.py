"""Safe frozen-handler extraction and semantic-corpus coverage controls."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_pe_strlen_reference as reference


class StrlenReferenceTests(unittest.TestCase):
    def test_reference_runs_without_importing_speakeasy(self):
        with patch.dict(sys.modules, {'speakeasy': None, 'speakeasy.common': None}):
            factory, source_hash = reference.handler()
            self.assertEqual(64, len(source_hash))
            memory = reference.Memory()
            memory.memory[:4] = b'abc\0'
            self.assertEqual(3, factory()._length(memory, 'lstrlenA', None, [reference.BASE]))

    def test_corpus_covers_all_narrow_bytes_and_wide_and_limit_boundaries(self):
        narrow = reference.specifications(False, 64)
        self.assertEqual(256, sum(c['label'].startswith('byte-') for c in narrow))
        wide = reference.specifications(True, 64)
        labels = {c['label'] for c in wide}
        self.assertTrue({'null', 'unmapped', 'overflow', 'unreadable', 'surrogate-pair',
                         'reversed-surrogates', 'odd-address', 'boundary-half-unit',
                         'length-32766', 'length-32767', 'length-32768'} <= labels)

    def test_undefined_cp1252_and_unpaired_utf16_fail_without_changing_last_error(self):
        factory, _ = reference.handler()
        for export, data in [('lstrlenA', b'\x81\0'), ('lstrlenW', b'\x00\xd8\0\0')]:
            memory = reference.Memory()
            memory.memory[:len(data)] = data
            self.assertEqual(0, factory()._length(memory, export, None, [reference.BASE]))
            self.assertEqual(0x12345678, memory.last_error)


if __name__ == '__main__':
    unittest.main()
