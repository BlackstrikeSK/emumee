"""Source edits and missing generated utilities must invalidate a frozen worker."""

import json
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from emumee.worker_build import RECEIPT, verify_receipt, write_receipt


class WorkerBuildTests(unittest.TestCase):
    def fixture(self, root):
        for name in ('Emumee.spec','launcher.py','pyproject.toml','build.ps1','tools/patch_bootloader_cfg.py','src/emumee/model.py'):
            path=root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('# harmless fixture\n',encoding='utf-8')
        worker=root/'dist/Emumee/Emumee.exe'
        worker.parent.mkdir(parents=True)
        worker.write_bytes(b'MZ receipt test only')
        for folder in (root/'src/emumee/guest_native',worker.parent/'_internal/emumee/guest_native'):
            folder.mkdir(parents=True)
            (folder/'ping_query_x64.exe').write_bytes(b'MZ guest fixture')
        return worker

    def test_source_edit_invalidates_worker_but_portable_bundle_needs_no_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            worker=self.fixture(root)
            expected=write_receipt(worker,root)
            self.assertEqual(verify_receipt(worker,root),expected)
            (root/'src/emumee/model.py').write_text('# changed model\n',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'stale'):
                verify_receipt(worker,root)
            self.assertEqual(verify_receipt(worker),expected)

    def test_missing_modified_assets_and_executable_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            worker=self.fixture(root)
            write_receipt(worker,root)
            asset=worker.parent/'_internal/emumee/guest_native/ping_query_x64.exe'
            asset.write_bytes(b'MZ modified asset')
            with self.assertRaisesRegex(ValueError,'guest utilities differ'):
                verify_receipt(worker)
            with self.assertRaisesRegex(ValueError,'differ from source'):
                write_receipt(worker,root)
            asset.write_bytes(b'MZ guest fixture')
            worker.write_bytes(b'MZ modified worker')
            with self.assertRaisesRegex(ValueError,'executable does not match'):
                verify_receipt(worker)
            asset.unlink()
            with self.assertRaisesRegex(ValueError,'assets are missing'):
                write_receipt(worker,root)

    def test_missing_malformed_and_unknown_build_receipt_fail_before_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            worker=self.fixture(root)
            with self.assertRaisesRegex(ValueError,'receipt missing'):
                verify_receipt(worker,root)
            path=worker.parent/RECEIPT
            for data in ('not-json','[]',json.dumps({'schema':2,'worker_sha256':'0'*64})):
                path.write_text(data,encoding='utf-8')
                with self.subTest(data=data), self.assertRaises(ValueError):
                    verify_receipt(worker,root)

    def test_cli_rejects_missing_receipt_before_parsing_sample_or_starting_container(self):
        from emumee.cli import run
        with tempfile.TemporaryDirectory() as directory:
            worker=self.fixture(Path(directory))
            errors=io.StringIO()
            with patch('emumee.cli._worker_bundle',return_value=worker), patch('emumee.cli.AppContainer') as sandbox:
                with contextlib.redirect_stderr(errors):
                    result=run(SimpleNamespace(sample='must-not-read-this.exe'))
            self.assertEqual(result,2)
            self.assertIn('build.ps1',errors.getvalue())
            sandbox.assert_not_called()


if __name__=='__main__':
    unittest.main()
