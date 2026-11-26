"""Candidate frozen Windows-string observations over bounded synthetic memory."""
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'Cargo.toml').exists())
SOURCE = 'src/emumee/winstrings.py'
BASE, SIZE = 0x26000000, 65536
METHODS = {
    'CompareStringA': ('_compare', (2,4)),
    'CompareStringW': ('_compare', (2,4)),
    'FindStringOrdinal': ('_find_ordinal', (1,3)),
    'WideCharToMultiByte': ('_wide_char_to_multi_byte', (2,4,6,7)),
    'CharUpperW': ('_char_upper_w', (0,)),
    '_wcslwr': ('_wcslwr', (0,)),
    'StrTrimW': ('_trim', (0,1)),
    'RtlOemToUnicodeN': ('_oem_to_unicode', (0,2,3)),
    'RtlIsTextUnicode': ('_is_text_unicode', (0,2)),
    'CharToOemA': ('_char_to_oem_a', (0,1)),
    'ApiSetQueryApiSetPresence': ('_api_set_presence', (0,1)),
}

def handler():
    raw = (ROOT/SOURCE).read_bytes()
    frozen = json.loads((ROOT/'rust/api-parity/legacy-inventory.json').read_bytes())
    assert hashlib.sha256(raw).hexdigest() == frozen['sources'][SOURCE]
    tree = ast.parse(raw)
    owner, = [n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='GuestStrings']
    owner = copy.deepcopy(owner)
    owner.body = [n for n in owner.body if isinstance(n,ast.FunctionDef) and n.name!='install']
    constants = [n for n in tree.body if isinstance(n,ast.Assign)]
    namespace = dict(common=SimpleNamespace(PERM_MEM_READ=1,PERM_MEM_WRITE=2))
    exec(compile(ast.Module(body=constants+[owner],type_ignores=[]),SOURCE,'exec'),namespace)
    return namespace['GuestStrings'],frozen

class Memory:
    def __init__(self,width,prot):
        self.width,self.prot=width,prot
        self.memory=bytearray(SIZE)
        self.last_error=0x12345678
    def get_address_map(self,address):
        if BASE<=address<BASE+SIZE:
            return SimpleNamespace(base=BASE,size=SIZE,free=False,prot=self.prot)
    def mem_read(self,address,size):
        assert self.prot&1 and BASE<=address and address+size<=BASE+SIZE
        return bytes(self.memory[address-BASE:address-BASE+size])
    def mem_write(self,address,value):
        assert self.prot&2 and BASE<=address and address+len(value)<=BASE+SIZE
        self.memory[address-BASE:address-BASE+len(value)]=value
    def set_last_error(self,value):self.last_error=value
    def get_ptr_size(self):return self.width

def relocated(address):
    return BASE+address-0x1000 if 0x1000<=address<0x11000 else address

def specifications():
    old=json.loads((ROOT/'rust/emumee-engine/src/api/winstrings_reference.json').read_bytes())
    for number,row in enumerate(old['cases']):
        name=row['export']
        if name not in METHODS:continue
        _,pointers=METHODS[name]
        args=list(row['arguments'])
        for index in pointers:args[index]=relocated(args[index])
        patches=[]
        for patch in row['patches']:
            data=bytes.fromhex(patch['hex'])
            if name=='ApiSetQueryApiSetPresence' and patch['address']==0x2000:
                offset=8 if row['width']==8 else 4
                pointer=int.from_bytes(data[offset:offset+row['width']],'little')
                data=data[:offset]+relocated(pointer).to_bytes(row['width'],'little')
            patches.append(dict(address=relocated(patch['address']),hex=data.hex()))
        yield dict(label=f'vector-{number:03}',export=name,width=row['width'],arguments=args,patches=patches,protection=3)
        if name=='CharUpperW':
            # A low word selects scalar mapping; a mapped pointer selects the buffer path.
            yield dict(label=f'scalar-{number:03}',export=name,width=row['width'],arguments=row['arguments'],patches=patches,protection=3)
    for name,(_,pointers) in METHODS.items():
        for width in (4,8):
            selected=next(s for s in specifications_base(old,name,width))
            for prot in (0,1,2):
                yield dict(selected,label=f'permission-{prot}',protection=prot)
            for index in pointers:
                args=list(selected['arguments']);args[index]=0
                yield dict(selected,label=f'null-{index}',arguments=args)

def specifications_base(old,name,width):
    # Select the ordinary relocated vector without recursively expanding negatives.
    row=next(r for r in old['cases'] if r['export']==name and r['width']==width)
    args=list(row['arguments'])
    for i in METHODS[name][1]:args[i]=relocated(args[i])
    patches=[]
    for patch in row['patches']:
        data=bytes.fromhex(patch['hex'])
        if name=='ApiSetQueryApiSetPresence' and patch['address']==0x2000:
            offset=8 if width==8 else 4
            data=data[:offset]+relocated(int.from_bytes(data[offset:offset+width],'little')).to_bytes(width,'little')
        patches.append(dict(address=relocated(patch['address']),hex=data.hex()))
    yield dict(export=name,width=width,arguments=args,patches=patches,protection=3)

def observe(*, include_diagnostics=False):
    factory,inventory=handler()
    contracts=[]
    for row in inventory['entries']:
        if row['export'] in METHODS and row['kind']=='function' and row['source']==SOURCE:
            contracts.append(row)
    # Inventory can contain multiple activation sites for one public identity.
    modules={name:sorted({r['module'] for r in contracts if r['export']==name}) for name in METHODS}
    cases=[]
    for spec in specifications():
        for module in modules[spec['export']]:
            memory=Memory(spec['width'],spec['protection']);api=factory()
            for patch in spec['patches']:
                data=bytes.fromhex(patch['hex']);offset=patch['address']-BASE
                assert 0<=offset and offset+len(data)<=SIZE
                memory.memory[offset:offset+len(data)]=data
            try:
                result=getattr(api,METHODS[spec['export']][0])(memory,module+'.'+spec['export'],None,list(spec['arguments']))
                outcome=dict(result=result&((1<<(8*spec['width']))-1),error=None)
            except (ValueError,OverflowError,AssertionError) as error:
                outcome=dict(result=None,error=type(error).__name__)
            observation = dict(module=module, **spec, **outcome, last_error=memory.last_error,
                memory_sha256=hashlib.sha256(memory.memory).hexdigest(), unsupported=bool(api.unsupported))
            if include_diagnostics:
                observation['legacy_diagnostics'] = api.unsupported
            cases.append(observation)
    identities=[list(key) for key in sorted({(c['module'],c['export'],'function','x64' if c['width']==8 else 'x86') for c in cases})]
    return dict(schema=1,scope='Candidate reference; no qualification or publication',source=SOURCE,
        source_sha256=inventory['sources'][SOURCE],contracts=identities,cases=cases)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--output',type=Path,default=ROOT/'rust/emumee-engine/src/api/winstrings_semantic_reference.json')
    options=parser.parse_args();document=observe();output=options.output
    if options.check:assert json.loads(output.read_bytes())==document,'Frozen string observations drifted'
    else:
        assert not output.exists(),'Preserve observations; use --check'
        output.write_text(json.dumps(document,indent=2)+'\n')
    print(json.dumps(dict(contracts=len(document['contracts']),cases=len(document['cases']))))
