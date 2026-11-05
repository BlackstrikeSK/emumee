"""Integrity controls for checked-in frozen ABI vectors; no guest execution."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import native_pe_abi_reference as reference


class AbiReferenceTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((ROOT / "rust/api-parity/abi-float-reference.json").read_bytes())

    def test_math_reference_has_real_builtin_pow_and_exact_signed_zero(self):
        rows = {(row["api"], tuple(row["arguments"])): row for row in self.document["vectors"]}
        self.assertEqual(len(rows), 143)
        self.assertEqual(rows["pow", ("4000000000000000", "4008000000000000")]["result"], "4020000000000000")
        self.assertEqual(rows["floor", ("8000000000000000",)]["result"], "0000000000000000")
        self.assertEqual(rows["sin", ("8000000000000000",)]["result"], "8000000000000000")

    def test_domain_and_overflow_are_not_successful_nan_results(self):
        rows = {(row["api"], tuple(row["arguments"])): row for row in self.document["vectors"]}
        for key in [("floor", ("7ff0000000000000",)), ("sin", ("fff0000000000000",)),
                    ("pow", ("0000000000000000", "bff0000000000000")),
                    ("pow", ("c000000000000000", "3fe0000000000000"))]:
            self.assertIn("error", rows[key])
            self.assertNotIn("result", rows[key])

    def test_transport_dimensions_and_raw_x86_float_bits_are_preserved(self):
        rows = self.document["transport"]["vectors"]
        self.assertEqual(len(rows), 56)
        self.assertEqual({row["architecture"] for row in rows}, {"x86", "x64"})
        self.assertEqual({row["convention"] for row in rows}, {"stdcall", "cdecl", "fastcall", "float"})
        for row in rows:
            self.assertEqual(len(row["arguments"]), row["count"])
            if row["architecture"] == "x86" and row["convention"] == "float":
                self.assertTrue(all(value > 0xffffffff for value in row["arguments"]))
                self.assertEqual(row["returned_sp"], 0x2004 + row["count"] * 4)

    @unittest.skipUnless((ROOT / ".venv/Lib/site-packages/speakeasy/binemu.py").is_file(), "Frozen source dependency is not installed")
    def test_fresh_isolated_source_capture_matches_checked_in_reference(self):
        source = ROOT / self.document["source"]
        self.assertEqual(reference.capture(source), self.document)


if __name__ == "__main__":
    unittest.main()
