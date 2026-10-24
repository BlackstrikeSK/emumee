"""Compare optimized sentinel bytes and bindings with the pinned engine."""

import copy
import unittest
from types import SimpleNamespace
from speakeasy.windows.common import _PeParser
from emumee.pe_imports import batched_import_patching, patch_imports_once


class PEImportTests(unittest.TestCase):
    def test_import_bytes_and_order_match_engine_for_both_widths(self):
        for width in (4, 8):
            parser = SimpleNamespace(imports={0x1100: ("ntoskrnl", "First"),
                                             0x1200: ("ntoskrnl", "Second")},
                                     mapped_image=bytes(0x1000), base=0x1000,
                                     ptr_size=width, imp_id=0xFEEDF00C, imp_step=4,
                                     import_table={})
            reference = copy.deepcopy(parser)
            _PeParser._patch_imports(reference)
            patch_imports_once(parser)
            self.assertEqual(vars(parser), vars(reference))

    def test_scope_is_restored_after_failure(self):
        original = _PeParser._patch_imports
        with self.assertRaisesRegex(ValueError, "test"):
            with batched_import_patching():
                self.assertIs(_PeParser._patch_imports, patch_imports_once)
                raise ValueError("test")
        self.assertIs(_PeParser._patch_imports, original)

    def test_outside_image_import_cannot_resize_image(self):
        parser = SimpleNamespace(imports={0x5000: ("ntoskrnl", "Bad")},
                                 mapped_image=bytes(0x1000), base=0x1000,
                                 ptr_size=8, imp_id=0xFEEDF00C, imp_step=4, import_table={})
        with self.assertRaisesRegex(ValueError, "outside"):
            patch_imports_once(parser)
        self.assertEqual(len(parser.mapped_image), 0x1000)
