"""Coverage controls for the M8 contained replay set; no guest execution."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from native_pe_m8 import cases, required_cases


def _populate(fixtures, names):
    for name in names:
        directory = fixtures / name
        directory.mkdir()
        (directory / 'source-execution.json').write_text('{}', encoding='utf-8')


class M8ControlSetTests(unittest.TestCase):
    def test_controls_cover_every_family_and_architecture(self):
        names = required_cases()
        self.assertEqual(34, len(names))
        for arch in ('X86', 'X64'):
            # The built-in indicator scan, the custom bounded-matcher pattern
            # and the executable-region carve are separate controls, so a
            # failure names the surface that produced it.
            for required in (f'{arch}-m8-strings-Builtin',
                             f'{arch}-m8-strings-Custom',
                             f'{arch}-m8-strings-Private',
                             f'{arch}-m8-strings-PrivatePrefix',
                             f'{arch}-m8-strings-PrivateExhausted',
                             f'{arch}-m8-strings-Module',
                             f'{arch}-m8-strings-ModulePrefix',
                             f'{arch}-m8-strings-ModuleExhausted',
                             f'{arch}-m8-carve-Shellcode',
                             f'{arch}-m8-carve-Released',
                             f'{arch}-m8-carve-DroppedPe',
                             f'{arch}-m8-carve-RemoteWrite',
                             f'{arch}-m8-carve-RemotePe',
                             f'{arch}-m8-carve-RemoteDisabled',
                             f'{arch}-m8-carve-SelfWrite',
                             f'{arch}-m8-carve-RemoteFailed',
                             f'{arch}-m8-carve-RemoteZero'):
                self.assertIn(required, names)

    def test_missing_or_unexpected_m8_control_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = root / 'fixtures-final'
            fixtures.mkdir()
            with self.assertRaises(AssertionError):
                cases(root)
            _populate(fixtures, required_cases())
            # Controls from an earlier milestone are not part of this set.
            _populate(fixtures, ['X64-m7-network-Dns'])
            self.assertEqual(34, len(cases(root)))
            _populate(fixtures, ['X64-m8-strings-invented'])
            with self.assertRaises(AssertionError):
                cases(root)

    def test_a_control_without_its_source_outcome_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = root / 'fixtures-final'
            fixtures.mkdir()
            _populate(fixtures, required_cases())
            (fixtures / 'X86-m8-strings-Custom/source-execution.json').unlink()
            with self.assertRaises(AssertionError):
                cases(root)


if __name__ == '__main__':
    unittest.main()
