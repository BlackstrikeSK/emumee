"""A sealed JSON file cannot hide changed raw evidence or another contract/build."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from native_pe_semantic_proofs import verify_artifacts, contract_identities
from native_pe_worklist import fingerprint


def record(root,path):
    data=path.read_bytes()
    return dict(path=path.relative_to(root).as_posix(),size=len(data),sha256=hashlib.sha256(data).hexdigest())


class SemanticProofChainTests(unittest.TestCase):
    def test_producer_identities_survive_json_roundtrip_and_reject_duplicates(self):
        row=dict(module='kernel32',export='Example',architecture='x64')
        identities=contract_identities([row])
        self.assertEqual(identities,json.loads(json.dumps(identities)))
        self.assertEqual([['kernel32','Example','function','x64']],identities)
        with self.assertRaisesRegex(AssertionError,'Duplicate'):contract_identities([row,row])

    def fixture(self,root,mutate=None):
        bundle=root/'bundle';bundle.mkdir()
        artifacts=[]
        for name in ('emumee-rs.exe','emumee-worker.exe','unicorn.dll'):
            path=bundle/name;path.write_bytes(name.encode());artifacts.append(record(root,path))
        (bundle/'rust-worker-build.json').write_text(json.dumps(dict(source_tree_sha256='c'*64)))
        raw=root/'raw.bin';raw.write_bytes(b'raw!');artifacts.append(record(root,raw))
        proof=dict(schema=1,profile='emumee.native-semantic.legacy-literals.v1',runtime_fingerprint='a'*64,
            source_tree_sha256='c'*64,contract_identities=[['kernel32','Example','function','x64']],artifacts=artifacts)
        if mutate:mutate(proof)
        proof['fingerprint']=fingerprint(proof)
        path=root/'proof.json';path.write_text(json.dumps(proof))
        row=dict(module='kernel32',export='Example',kind='function',architecture='x64',
            source_fingerprint='b'*64,semantic_status='verified_model',submitted_route='verified',
            behavioral_evidence=[dict(id='example',architecture='x64',source_fingerprint='b'*64,
                oracle='synthetic test',baseline='frozen',limits=dict(bytes=4),tests=['positive'],
                negative_controls=['tamper'],artifacts=[record(root,path)])])
        return bundle,raw,row

    def verify(self,root,bundle,row):
        return verify_artifacts([row],root,bundle=bundle,runtime_fingerprint='a'*64)

    def test_valid_proof_traverses_raw_artifacts_and_exact_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle,_,row=self.fixture(root)
            self.assertEqual(5,self.verify(root,bundle,row))

    def test_changed_or_missing_raw_output_is_rejected_even_with_unchanged_proof(self):
        for missing in (False,True):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);bundle,raw,row=self.fixture(root)
                if missing:raw.unlink()
                else:raw.write_bytes(b'evil')
                with self.assertRaises(AssertionError):self.verify(root,bundle,row)

    def test_stale_runtime_or_source_build_cannot_be_resigned_into_current_evidence(self):
        for key in ('runtime_fingerprint','source_tree_sha256'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);bundle,_,row=self.fixture(root,lambda p:p.update({key:'d'*64}))
                with self.assertRaises(AssertionError):self.verify(root,bundle,row)

    def test_another_binary_from_same_source_build_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle,_,row=self.fixture(root)
            (bundle/'emumee-worker.exe').write_bytes(b'different current worker')
            with self.assertRaises(AssertionError):self.verify(root,bundle,row)

    def test_missing_or_wrong_contract_identity_cannot_close_a_row(self):
        for identities in ([],[['kernel32','Different','function','x64']]):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);bundle,_,row=self.fixture(root,lambda p:p.update(contract_identities=identities))
                with self.assertRaises(AssertionError):self.verify(root,bundle,row)

    def test_a_raw_oracle_file_alone_is_not_a_submitted_route_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle,raw,row=self.fixture(root)
            row['behavioral_evidence'][0]['artifacts']=[record(root,raw)]
            with self.assertRaisesRegex(AssertionError,'absent'):self.verify(root,bundle,row)


if __name__=='__main__':unittest.main()
