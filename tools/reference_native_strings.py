"""Freeze trusted legacy string-handler observations against fake guest memory.

This never loads or executes a PE, guest instruction, or native Windows export.
"""
import hashlib
import json
from pathlib import Path
import sys
import argparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from emumee.winstrings import GuestStrings
import speakeasy.common as common

BASE, SIZE = 0x1000, 0x10000
class Mapping:
    base, size, free, prot = BASE, SIZE, False, common.PERM_MEM_READ | common.PERM_MEM_WRITE
class Memory:
    def __init__(self, width):
        self.memory = bytearray(SIZE)
        self.last_error = 0x12345678
        self.width = width
    def get_address_map(self, at):
        return Mapping() if BASE <= at < BASE + SIZE else None
    def mem_read(self, at, size):
        assert BASE <= at and at + size <= BASE + SIZE
        return bytes(self.memory[at-BASE:at-BASE+size])
    def mem_write(self, at, data):
        assert BASE <= at and at + len(data) <= BASE + SIZE
        self.memory[at-BASE:at-BASE+len(data)] = data
    def set_last_error(self, value):
        self.last_error = value
    def get_ptr_size(self):
        return self.width

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--refresh-baseline', action='store_true')
options = parser.parse_args()
cases = []
assert GuestStrings()._access(Memory(4), BASE, 16)
assert GuestStrings()._writable(Memory(4), BASE, 16)
def add(name, method, args, patches, widths=(4,8)):
    for width in widths:
        memory = Memory(width)
        for at, value in patches:
            memory.mem_write(at, value)
        api = GuestStrings()
        result = getattr(api, method)(memory, name, None, args)
        cases.append(dict(width=width, module=name.split('.')[0], export=name.split('.')[1],
                          arguments=[v & ((1 << (width*8))-1) for v in args],
                          patches=[dict(address=at, hex=value.hex()) for at,value in patches],
                          result=result & ((1 << (width*8))-1), last_error=memory.last_error,
                          memory_sha256=hashlib.sha256(memory.memory).hexdigest(),
                          unsupported=bool(api.unsupported)))

def wide(s): return (s+'\0').encode('utf-16le')
for suffix in ('A','W'):
    encode = wide if suffix=='W' else lambda s:(s+'\0').encode('cp1252')
    for left,right in [('ALPHA','alpha'),('Alpha','Beta'),('é','e'),('','')]:
        for flags in (0,1,0x30001,2):
            add('kernel32.CompareString'+suffix,'_compare',[0x400,flags,0x1000,-1,0x2000,-1],[(0x1000,encode(left)),(0x2000,encode(right))])
    for source in (0,0x1000,BASE+SIZE-1):
        add('kernel32.lstrlen'+suffix,'_length',[source],[(0x1000,encode('A😀' if suffix=='W' else 'Aé'))])
for source,needle in [('AlphaBetaBeta','beta'),('😀Beta','Beta'),('Alpha',''),('','A')]:
    for flags in (0x100000,0x200000,0x400000,0x800000,0):
        for ignore in (0,1,2):
            add('kernel32.FindStringOrdinal','_find_ordinal',[flags,0x1000,-1,0x2000,-1,ignore],[(0x1000,wide(source)),(0x2000,wide(needle))])
for page in (437,850,1252,65001,0,1,999):
    for value in ('Coffee','éø😀?', 'A\0B'):
        for capacity in (0,2,32):
            add('kernel32.WideCharToMultiByte','_wide_char_to_multi_byte',[page,0,0x1000,len(value.encode('utf-16le'))//2,0x3000,capacity,0,0],[(0x1000,value.encode('utf-16le'))])
for page,flags,count,output,capacity,default,used in [(1252,0,-1,0x3000,32,0x2000,0x4000),(1252,0,-1,0x3000,0,0x2000,0x4000),(65001,0,-1,0x3000,32,0,0),(65001,0,-1,0x3000,32,0,0x4000),(437,1,1,0x3000,32,0,0),(437,0,0,0x3000,32,0,0),(437,0,1,0x1000,32,0,0),(437,0,1,0,32,0,0),(437,0,1,0x3000,0x80000000,0,0)]:
    add('kernel32.WideCharToMultiByte','_wide_char_to_multi_byte',[page,flags,0x1000,count,output,capacity,default,used],[(0x1000,wide('😀é')),(0x2000,b'!')])
for name,method in [('user32.CharUpperW','_char_upper_w'),('ucrtbase._wcslwr','_wcslwr')]:
    for value in ('aBc','é',''):
        add(name,method,[0x1000],[(0x1000,wide(value))])
for value,trim in [('  Alpha  ',' '),('Alpha',' '),('éAlphaé','é'),('',' ')]:
    add('shlwapi.StrTrimW','_trim',[0x1000,0x2000],[(0x1000,wide(value)),(0x2000,wide(trim))])
for capacity in (0,1,2,4,6):
    for value in (b'A\n',b'\xff\n'):
        add('ntdll.RtlOemToUnicodeN','_oem_to_unicode',[0x3000,capacity,0x4000,0x1000,2],[(0x1000,value)])
for value in (b'Milk\nCoffee\nBread\n',b'A\0B\0',b'\xff\xfeA\0',b'\xfe\xff\0A',b'ABC',b''):
    for mask in (0xffffffff,2,0):
        add('ntdll.RtlIsTextUnicode','_is_text_unicode',[0x1000,len(value),0x4000],[(0x1000,value),(0x4000,mask.to_bytes(4,'little'))])
for value in ('ASCII','é',''):
    add('user32.CharToOemA','_char_to_oem_a',[0x1000,0x3000],[(0x1000,(value+'\0').encode('cp1252'))])
for namespace in ('ext-ms-win-fsutilext-ulib-l1-1-0','api-ms-win-missing-l1-1-0','invalid'):
    for width in (4,8):
        value=namespace.encode('utf-16le');header=len(value).to_bytes(2,'little')*2+b'\0'*(4 if width==8 else 0)+(0x1000).to_bytes(width,'little')
        add('api-ms-win-core-apiquery-l1-1-0.ApiSetQueryApiSetPresence','_api_set_presence',[0x2000,0x3000],[(0x1000,value),(0x2000,header)],(width,))
document=dict(schema=1,reference_sha256=hashlib.sha256((ROOT/'src/emumee/winstrings.py').read_bytes()).hexdigest(),cases=cases)
output=ROOT/'rust/emumee-engine/src/api/winstrings_reference.json'
content = json.dumps(document,ensure_ascii=False,indent=2)+'\n'
if output.exists() and output.read_text(encoding='utf-8') != content and not options.refresh_baseline:
    parser.error('Trusted-handler observations changed; inspect the baseline before --refresh-baseline.')
output.write_text(content,encoding='utf-8')
print(f'{len(cases)} trusted-handler observations saved to {output}')
