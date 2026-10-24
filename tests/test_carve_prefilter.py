"""Random packed bytes must not cause large copies for every accidental MZ."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from emumee.artifacts import ArtifactCatalog, _is_pe
from tests.fixtures.build_native import build


class CarvePrefilterTests(unittest.TestCase):
    def test_false_signatures_are_skipped_and_real_embedded_pe_survives(self):
        blob = b"MZ" + bytes(1022)
        payload = build(0x8664)
        blob = blob * 8192 + payload
        with tempfile.TemporaryDirectory() as directory:
            catalog = ArtifactCatalog(Path(directory))
            with patch("emumee.artifacts._is_pe", wraps=_is_pe) as check:
                catalog.carve_pe(blob, "packed")
            self.assertEqual(check.call_count, 1)
            self.assertEqual(len(catalog.items), 1)
            self.assertEqual((Path(directory) / catalog.items[0]["file"]).read_bytes(), payload)

    def test_short_or_outside_signature_is_not_a_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog = ArtifactCatalog(Path(directory))
            with patch("emumee.artifacts._is_pe", side_effect=AssertionError("Unexpected parser")):
                catalog.carve_pe(b"MZ" + bytes(100) + b"MZ", "short")
            self.assertEqual(catalog.items, [])
