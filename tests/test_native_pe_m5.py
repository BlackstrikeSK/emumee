"""Coverage controls for the M5 contained replay set; no guest execution."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from native_pe_m5 import cases, required_cases


class M5ControlSetTests(unittest.TestCase):
    def test_controls_cover_every_family_architecture_and_budget_stop(self):
        names = required_cases()
        self.assertEqual(110, len(names))
        for arch in ('X86', 'X64'):
            for required in (f'{arch}-m5-crt-data-Parent-20000',
                             f'{arch}-m5-crt-data-Nx-20000',
                             f'{arch}-m5-crt-data-Alias-1',
                             f'{arch}-m5-win-alloc-OwnedFree',
                             f'{arch}-m5-crt-runtime-Atexit',
                             f'{arch}-m5-crt-text-Clock',
                             f'{arch}-m5-win-text-Message',
                             f'{arch}-m5-crt-service-Scan',
                             f'{arch}-m5-crt-file-Streams',
                             f'{arch}-m5-compiled-crt_program',
                             f'{arch}-m5-compiled-crt_refusal'):
                self.assertIn(required, names)

    def test_missing_or_unexpected_m5_control_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = root / 'fixtures-final'
            fixtures.mkdir()
            with self.assertRaises(AssertionError):
                cases(root)
            for name in required_cases():
                (fixtures / name).mkdir()
            (fixtures / 'X64-m4-existing-control').mkdir()
            self.assertEqual(110, len(cases(root)))
            (fixtures / 'X64-m5-crt-data-invented').mkdir()
            with self.assertRaises(AssertionError):
                cases(root)


if __name__ == '__main__':
    unittest.main()
