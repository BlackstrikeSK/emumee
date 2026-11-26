"""Frozen CRT data callbacks over fake allocation and byte storage only."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import types

from native_pe_batches import inventory_contracts

ROOT=Path(__file__).resolve().parents[1]
SOURCE='.venv/Lib/site-packages/speakeasy/winenv/api/usermode/msvcrt.py'


def observe():
    frozen=json.loads((ROOT/'rust/api-parity/legacy-inventory.json').read_bytes())
    raw=(ROOT/SOURCE).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==frozen['sources'][SOURCE]
    contracts=inventory_contracts(frozen);tree=ast.parse(raw);functions=[];rows=[]
    for name,kind in (('_acmdln','data'),('__p__acmdln','function')):
        for arch in ('x86','x64'):
            refs=contracts['msvcrt',name,kind,arch]
            assert len(refs)==1 and refs[0]['source']==SOURCE
            rows.append(dict(module='msvcrt',export=name,kind=kind,architecture=arch,reference_sources=refs))
        fn,=[n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.lineno==refs[0]['line']]
        fn=copy.deepcopy(fn);fn.decorator_list=[];fn.returns=None
        for arg in fn.args.args:arg.annotation=None
        functions.append(fn)
    namespace={};exec(compile(ast.fix_missing_locations(ast.Module(body=functions,type_ignores=[])),SOURCE,'exec'),namespace)

    class Memory:
        def __init__(self,width):
            self.width=width;self.next=0x31000000;self.regions={};self.emu=self
            self._acmdln=types.MethodType(namespace['_acmdln'],self)
        def get_argv(self):return ['sample.exe','two words']
        def get_ptr_size(self):return self.width
        def mem_alloc(self,size,base=None,tag=None):
            address=self.next;self.next=(address+size+15)&~15;self.regions[address]=bytearray(size);return address
        def mem_write(self,address,data):
            base,region=next((b,r) for b,r in self.regions.items() if b<=address and address+len(data)<=b+len(r))
            region[address-base:address-base+len(data)]=data
        def pointer(self,address):
            base,region=next((b,r) for b,r in self.regions.items() if b<=address and address+self.width<=b+len(r))
            return int.from_bytes(region[address-base:address-base+self.width],'little')

    cases=[]
    for arch,width in (('x86',4),('x64',8)):
        memory=Memory(width);cell=memory._acmdln();memory.mem_write(cell,(0x12345000).to_bytes(width,'little'))
        first=namespace['__p__acmdln'](memory,None,[],{});second=namespace['__p__acmdln'](memory,None,[],{})
        assert cell!=first and first!=second and memory.pointer(first)!=0x12345000
        allocations=len(memory.regions);provided=memory._acmdln(ptr=0x12346000)
        assert provided==0x12346000 and len(memory.regions)==allocations
        cases.append(dict(architecture=arch,width=width,imported_cell=cell,first_accessor_cell=first,
            second_accessor_cell=second,imported_pointer=memory.pointer(cell),accessor_pointer=memory.pointer(first),
            provided_pointer=provided,allocations=allocations))
    return dict(schema=1,source=SOURCE,source_sha256=hashlib.sha256(raw).hexdigest(),contracts=rows,cases=cases)
