import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from native_pe_staging import verify_run
from native_pe_staging_seal import binding
from native_pe_m2 import verify_control


class StagingEvidenceTests(unittest.TestCase):
    def control(self, root):
        run = root / 'control'
        (run / 'worker').mkdir(parents=True)
        documents = {
            'binding-verification.json': dict(schema=1, case='missing', architecture='x64', verified=True, worker_exit=2, cleanup='restored', request_sha256='a' * 64),
            'general-job-profile.json': dict(profile='submitted_user_1024_v1', cleanup='restored', peak_process_memory_bytes=8192,
                process_memory_bytes=1024 * 1024 * 1024, active_process_limit=1, network_capabilities=0,
                output_limits=dict(max_bytes=512 * 1024 * 1024, max_entries=4200, max_directories=8, max_depth=4)),
            'worker-stop.json': dict(cleanup='restored', worker=dict(reason='exited', exit_code=2)),
            'worker/containment.json': dict(app_container=True, job_object=True, child_process_blocked=True, network_capabilities=0),
        }
        for name, document in documents.items():
            (run / name).write_text(json.dumps(document), encoding='utf-8')
        raw = b'{}'
        (run / 'request.json').write_bytes(raw)
        receipt = documents['binding-verification.json']
        receipt['request_sha256'] = hashlib.sha256(raw).hexdigest()
        (run / 'binding-verification.json').write_text(json.dumps(receipt), encoding='utf-8')
        (run / 'worker/error.txt').write_text('Submitted slot inventory differs', encoding='utf-8')
        return run

    def test_m2_refusal_requires_resource_cleanup_and_nonpublication_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.control(Path(directory))
            verify_control(run, 'missing', 'X64')
            (run / 'worker/result.json').write_text('{}', encoding='utf-8')
            with self.assertRaises(AssertionError):
                verify_control(run, 'missing', 'X64')

    def test_m2_seal_rejects_resource_stop_and_containment_forgery(self):
        for name, key, value in [('general-job-profile.json', 'process_memory_bytes', 2**31),
                                  ('general-job-profile.json', 'peak_process_memory_bytes', 2**31),
                                  ('general-job-profile.json', 'cleanup', 'pending'),
                                  ('general-job-profile.json', 'active_process_limit', 2),
                                  ('worker/containment.json', 'network_capabilities', 1),
                                  ('worker-stop.json', 'cleanup', 'pending')]:
            with self.subTest(name=name, key=key), tempfile.TemporaryDirectory() as directory:
                run = self.control(Path(directory))
                document = json.loads((run / name).read_bytes())
                document[key] = value
                (run / name).write_text(json.dumps(document), encoding='utf-8')
                with self.assertRaises(AssertionError):
                    verify_control(run, 'missing', 'X64')

    def fixture(self, root):
        source = root / 'source.exe'
        source.write_bytes(b'controlled source')
        run = root / 'run'
        (run / 'worker').mkdir(parents=True)
        (run / 'inputs').mkdir()
        staged = b'staged bytes'
        (run / 'inputs/0000.bin').write_bytes(staged)
        sha = lambda raw: hashlib.sha256(raw).hexdigest()
        request = dict(schema=2, profile='submitted_user_pe_v1', run_id='fixture',
                       persona_sha256=sha(b'controlled persona'),
                       input_sha256=sha(source.read_bytes()), input_size=source.stat().st_size,
                       staged=[dict(size=len(staged), sha256=sha(staged))])
        raw = json.dumps(request).encode()
        (run / 'request.json').write_bytes(raw)
        (run / 'input.pe').write_bytes(source.read_bytes())
        (run / 'persona.json').write_bytes(b'controlled persona')
        result = dict(schema=1, profile=request['profile'], request_sha256=sha(raw),
                      input_receipt=request,
                      input_sha256=request['input_sha256'], run_id='fixture',
                      containment=dict(app_container=True, job_object=True, child_process_blocked=True, network_capabilities=0),
                      execution=dict(error=None, completion_reason='entry_return', guest_entry_return=42, artifacts=[]))
        raw_result = json.dumps(result).encode()
        (run / 'worker/result.json').write_bytes(raw_result)
        manifest = dict(result=result, request_sha256=sha(raw), result_sha256=sha(raw_result), cleanup='restored')
        (run / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        return run, source

    def test_independent_receipt_accepts_exact_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            run, source = self.fixture(Path(directory))
            verify_run(run, source, 0)
            binding(run, source)

    def test_independent_receipt_rejects_each_byte_authority_substitution(self):
        for name in ('request.json', 'input.pe', 'persona.json', 'inputs/0000.bin', 'worker/result.json'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                run, source = self.fixture(Path(directory))
                (run / name).write_bytes(b'changed')
                with self.assertRaises((AssertionError, ValueError)):
                    verify_run(run, source, 0)
                with self.assertRaises((AssertionError, ValueError)):
                    binding(run, source)

    def test_independent_receipt_rejects_cleanup_and_containment_forgery(self):
        for key in ('cleanup', 'result'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                run, source = self.fixture(Path(directory))
                manifest = json.loads((run / 'manifest.json').read_bytes())
                if key == 'cleanup':
                    manifest[key] = 'pending'
                else:
                    manifest[key]['containment']['app_container'] = False
                (run / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
                with self.assertRaises(AssertionError):
                    verify_run(run, source, 0)
                with self.assertRaises(AssertionError):
                    binding(run, source)


if __name__ == '__main__':
    unittest.main()
