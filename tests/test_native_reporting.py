"""Primary guest results must come from the executable entry."""

import unittest

from emumee.native import _primary_entry_return


class NativeReportingTests(unittest.TestCase):
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
