"""MSI intake and bounded static stream recovery."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from emumee.msi import inspect_msi
from emumee.pe import InvalidSample, MSI_SIGNATURE, inspect_pe_header
from tests.fixtures.build_native import build


class MsiTests(unittest.TestCase):
    def test_msi_family_requires_compound_signature(self):
        payload = MSI_SIGNATURE + bytes(504)
        for name in ("sample.msi", "patch.msp", "transform.mst"):
            info = inspect_pe_header(payload, name)
            self.assertEqual((info.kind, info.architecture), ("msi", "container"))
            with self.assertRaisesRegex(InvalidSample, "MSI database"):
                inspect_pe_header(b"MZ" + bytes(510), name)

    def test_static_stream_recovery_is_bounded_and_does_not_execute(self):
        payload = MSI_SIGNATURE + bytes(504)
        info = inspect_pe_header(payload, "sample.msi")
        pe = build(0x14C)

        class FakeOle:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def listdir(self, **_):
                return [["Binary", "Payload"], ["_Streams", "Cabinet"]]

            def get_size(self, parts):
                return len(pe) if parts[-1] == "Payload" else 4

            def openstream(self, parts):
                return io.BytesIO(pe if parts[-1] == "Payload" else b"MSCF")

        with tempfile.TemporaryDirectory() as temporary, patch(
                "emumee.msi.olefile.OleFileIO", return_value=FakeOle()):
            root = Path(temporary)
            result = inspect_msi(payload, info, root)
            report = json.loads((root / "engine-report.json").read_text())
            self.assertEqual(report["stream_count"], 2)
            self.assertEqual(report["streams"][0]["type"], "pe")
            self.assertEqual(report["streams"][1]["type"], "cabinet")
            self.assertEqual(result["completion_reason"], "static_inspection")
            self.assertEqual(result["instruction_count"], 0)
            self.assertEqual(len(result["artifacts"]), 2)
            self.assertTrue((root / "artifacts" / "manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
