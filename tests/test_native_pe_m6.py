"""Coverage controls for the M6 contained replay set; no guest execution."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from native_pe_m6 import cases, required_cases


class M6ControlSetTests(unittest.TestCase):
    def test_controls_cover_every_family_architecture_and_character_width(self):
        names = required_cases()
        self.assertEqual(154, len(names))
        for arch in ('X86', 'X64'):
            # Every width family emits both the narrow and the wide export.
            for family, case in (('registry', 'DeleteValue'), ('version', 'Verify'),
                                 ('locale', 'Firmware'), ('file', 'Information'),
                                 ('path', 'FindExBasic'), ('volume', 'MountPaths'),
                                 ('console', 'Handlers')):
                for width in ('A', 'W'):
                    self.assertIn(f'{arch}-m6-{family}-{case}{width}', names)
            # Every ownership and refusal boundary has its own control.
            for required in (f'{arch}-m6-registry-DeleteDeniedA',
                             f'{arch}-m6-file-DeniedA',
                             f'{arch}-m6-path-ShortNameUnsupportedW',
                             f'{arch}-m6-path-SearchLevelUnsupportedW',
                             f'{arch}-m6-unmap-SelfImage',
                             f'{arch}-m6-unmap-NotMapped',
                             f'{arch}-m6-unmap-Hollow',
                             f'{arch}-m6-observation-ImageWrite',
                             f'{arch}-m6-observation-WrittenCode',
                             f'{arch}-m6-compiled-m6_program',
                             f'{arch}-m6-compiled-m6_refusal'):
                self.assertIn(required, names)

    def test_missing_or_unexpected_m6_control_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = root / 'fixtures-final'
            fixtures.mkdir()
            with self.assertRaises(AssertionError):
                cases(root)
            for name in required_cases():
                (fixtures / name).mkdir()
            # Controls from an earlier milestone are not part of this set.
            (fixtures / 'X64-m5-crt-data-Alias-20000').mkdir()
            self.assertEqual(154, len(cases(root)))
            (fixtures / 'X64-m6-registry-invented').mkdir()
            with self.assertRaises(AssertionError):
                cases(root)


if __name__ == '__main__':
    unittest.main()
