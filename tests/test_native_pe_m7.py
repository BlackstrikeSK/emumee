"""Coverage controls for the M7 contained replay set; no guest execution."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from native_pe_m7 import cases, required_cases


def _populate(fixtures, names):
    for name in names:
        directory = fixtures / name
        directory.mkdir()
        (directory / 'source-execution.json').write_text('{}', encoding='utf-8')


class M7ControlSetTests(unittest.TestCase):
    def test_controls_cover_every_family_and_architecture(self):
        names = required_cases()
        self.assertEqual(70, len(names))
        for arch in ('X86', 'X64'):
            # Every family this milestone owns has its own controls.
            for family, case in (('resource', 'LoadString'), ('crypto', 'Rc4'),
                                 ('path', 'Edit'), ('com', 'Wbem'),
                                 ('security', 'Token'), ('socket', 'Transfer'),
                                 ('network', 'Addresses')):
                self.assertIn(f'{arch}-m7-{family}-{case}', names)
            # Every network concern is a separate control, so a failure names
            # the surface that produced it.
            for required in (f'{arch}-m7-network-Adapter',
                             f'{arch}-m7-network-Tables',
                             f'{arch}-m7-network-Icmp',
                             f'{arch}-m7-network-Dns',
                             f'{arch}-m7-network-Workstation',
                             f'{arch}-m7-network-Redirector',
                             f'{arch}-m7-network-CrackUrl',
                             f'{arch}-m7-network-Options',
                             f'{arch}-m7-network-WinHttp',
                             f'{arch}-m7-security-Audit',
                             f'{arch}-m7-com-Shell',
                             f'{arch}-m7-resource-Missing'):
                self.assertIn(required, names)

    def test_missing_or_unexpected_m7_control_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = root / 'fixtures-final'
            fixtures.mkdir()
            with self.assertRaises(AssertionError):
                cases(root)
            _populate(fixtures, required_cases())
            # Controls from an earlier milestone are not part of this set.
            _populate(fixtures, ['X64-m6-registry-DeleteValueA'])
            self.assertEqual(70, len(cases(root)))
            _populate(fixtures, ['X64-m7-network-invented'])
            with self.assertRaises(AssertionError):
                cases(root)

    def test_a_control_without_its_source_outcome_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = root / 'fixtures-final'
            fixtures.mkdir()
            _populate(fixtures, required_cases())
            (fixtures / 'X86-m7-network-Dns/source-execution.json').unlink()
            with self.assertRaises(AssertionError):
                cases(root)


if __name__ == '__main__':
    unittest.main()
