"""Profile a generated scalar copy/hash-style loop; never execute a real driver."""
import argparse
import cProfile
import io
import json
from pathlib import Path
import pstats
import struct
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tests.test_kernel_runtime import runtime_driver
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona


def scan_fixture(iterations=500):
    code=bytearray(bytes.fromhex('4881ec00020000'))
    code.extend(b'\xbb'+struct.pack('<I',iterations))
    code.extend(b'\x48\xbe'+struct.pack('<Q',0x140002100))
    outer=len(code)
    code.extend(bytes.fromhex('31d2'))
    inner=len(code)
    code.extend(bytes.fromhex('0fb7045666890454ffc281fa80000000'))
    code.extend(b'\x72'+struct.pack('<b',inner-(len(code)+2)))
    code.extend(bytes.fromhex('ffcb'))
    code.extend(b'\x75'+struct.pack('<b',outer-(len(code)+2)))
    code.extend(bytes.fromhex('4881c40002000031c0'))
    return runtime_driver(0x8664,['KeGetCurrentIrql'],[],[(0x2100,bytes(range(256)))],tail=bytes(code))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--iterations',type=int,default=500)
    parser.add_argument('--profile',action='store_true')
    args=parser.parse_args()
    root=args.output.resolve(); root.mkdir(parents=True,exist_ok=False)
    payload=scan_fixture(args.iterations)
    profile=cProfile.Profile()
    if args.profile: profile.enable()
    start=time.perf_counter()
    result=run_driver(payload,inspect_pe(payload,'generated-scan.sys'),load_persona(None),root,120,20_000_000)
    elapsed=time.perf_counter()-start
    if args.profile:
        profile.disable(); profile.dump_stats(str(root/'profile.pstats'))
        out=io.StringIO(); pstats.Stats(profile,stream=out).sort_stats('cumulative').print_stats(40)
        (root/'profile.txt').write_text(out.getvalue())
    assert result['guest_entry_return']==0 and not result['errors'],result['errors']
    report=json.loads((root/'engine-report.json').read_text())
    observation={'seconds':elapsed,'instruction_count':result['instruction_count'],
        'instruction_cache':report['instruction_cache'],'profiled':args.profile}
    (root/'timing.json').write_text(json.dumps(observation,indent=2))
    print(json.dumps(observation))


if __name__=='__main__': main()
