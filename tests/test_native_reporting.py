"""Primary guest results must come from the executable entry."""

import unittest

from emumee.native import _primary_entry_return, _engine_error_text
from emumee.reports import valid_summary


class NativeReportingTests(unittest.TestCase):
    def test_unsupported_api_name_survives_bounded_summary_formatting(self):
        message = _engine_error_text({"type": "unsupported_api", "api_name": "ntoskrnl.Missing\nApi",
            "pc": "0xfeedf07c", "context_summary": "detail" * 1000})
        self.assertIn("ntoskrnl.Missing Api", message)
        self.assertIn("0xfeedf07c", message)
        self.assertNotIn("\n", message)
        self.assertLessEqual(len(message), 1024)

    def test_long_run_instruction_counts_are_valid_without_relaxing_other_counters(self):
        base = {"id": "20261016T000000Z-12345678", "sample": {}, "status": "partial", "errors": []}
        for count in (303_029_526, 1_000_000_000, (1 << 64) - 1):
            self.assertTrue(valid_summary({**base, "instruction_count": count}))
        for count in (-1, True, 1 << 64):
            self.assertFalse(valid_summary({**base, "instruction_count": count}))
        self.assertFalse(valid_summary({**base, "denied_operations": 100_000_001}))

    def test_dll_initializer_return_is_not_reported_as_exe_return(self):
        entries = [
            {"ep_type": "static_dll_entry_ulib", "ret_val": "0x3f2101", "error": None},
            {"ep_type": "module_entry", "ret_val": "0x0", "error": None},
        ]
        self.assertEqual(_primary_entry_return(entries), 0)
        entries[1]["error"] = {"type": "invalid_fetch"}
        self.assertIsNone(_primary_entry_return(entries))
        self.assertIsNone(_primary_entry_return(entries[:1]))


if __name__ == "__main__":
    unittest.main()
