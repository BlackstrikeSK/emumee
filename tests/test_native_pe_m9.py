"""Coverage controls for the M9 contained replay set; no guest execution."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from native_pe_m9 import cases, required_cases


def _populate(fixtures, names):
    for name in names:
        directory = fixtures / name
        directory.mkdir()
        (directory / 'source-execution.json').write_text('{}', encoding='utf-8')


class M9ControlSetTests(unittest.TestCase):
    def test_controls_cover_every_operational_program_and_architecture(self):
        names = required_cases()
        self.assertEqual(6, len(names))
        for arch in ('X86', 'X64'):
            # Each operational program chains a distinct set of families, so a
            # failure names the integration that produced it.
            for required in (f'{arch}-m9-operational-Provisioning',
                             f'{arch}-m9-operational-Integrity',
                             f'{arch}-m9-operational-Networking'):
                self.assertIn(required, names)

    def test_missing_or_unexpected_m9_control_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = root / 'fixtures-final'
            fixtures.mkdir()
            with self.assertRaises(AssertionError):
                cases(root)
            _populate(fixtures, required_cases())
            # Controls from an earlier milestone are not part of this set.
            _populate(fixtures, ['X64-m8-carve-Shellcode'])
            self.assertEqual(6, len(cases(root)))
            _populate(fixtures, ['X64-m9-operational-invented'])
            with self.assertRaises(AssertionError):
                cases(root)

    def test_a_control_without_its_source_outcome_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = root / 'fixtures-final'
            fixtures.mkdir()
            _populate(fixtures, required_cases())
            (fixtures / 'X86-m9-operational-Integrity/source-execution.json').unlink()
            with self.assertRaises(AssertionError):
                cases(root)


if __name__ == '__main__':
    unittest.main()
