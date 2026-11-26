"""Frozen interlocked handlers over synthetic memory; no PE or host API execution."""
import argparse
import ast
import copy
import ctypes
import hashlib
import json
from pathlib import Path
from native_pe_batches import inventory_contracts
from native_pe_worklist import atomic_write

ROOT=Path(__file__).resolve().parents[1]
NAMES=['InterlockedIncrement','InterlockedDecrement','InterlockedExchangeAdd','InterlockedExchange','InterlockedCompareExchange']
SOURCE='.venv/Lib/site-packages/speakeasy/winenv/api/usermode/kernel32.py'


def _handlers():
    frozen=json.loads((ROOT/'rust/api-parity/legacy-inventory.json').read_bytes())
    contracts=inventory_contracts(frozen)
    source='.venv/Lib/site-packages/speakeasy/winenv/api/usermode/kernel32.py'
    raw=(ROOT/source).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==frozen['sources'][source]
    tree=ast.parse(raw)
    names=NAMES
    functions=[]
    for name in names:
        refs=contracts['kernel32',name,'function','x64']
        assert len(refs)==1 and refs[0]['source']==source
        function,=[n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name==name and n.lineno==refs[0]['line']]
        function=copy.deepcopy(function)
        function.decorator_list=[]
        function.returns=None
        for argument in [*function.args.posonlyargs,*function.args.args,*function.args.kwonlyargs]:
            argument.annotation=None
        assert not any(isinstance(n,(ast.Import,ast.ImportFrom)) for n in ast.walk(function))
        for node in ast.walk(function):
            if isinstance(node,ast.Call):
                assert isinstance(node.func,ast.Attribute) and node.func.attr in ('mem_read','mem_write','from_bytes','to_bytes','c_long')
        functions.append(function)
    namespace={'ct':ctypes}
    exec(compile(ast.fix_missing_locations(ast.Module(body=functions,type_ignores=[])),source,'exec'),namespace)
    return namespace,contracts,hashlib.sha256(raw).hexdigest()


class Memory:
    def __init__(self,old,readable=True,writable=True):
        self.data=bytearray([0xa5])*65536
        self.data[32:36]=old.to_bytes(4,'little')
        self.readable=readable
        self.writable=writable
        self.calls=[]
        self.last_error=0x12345678

    def mem_read(self,address,size):
        self.calls.append(['read',address,size])
        assert address==0x26000020 and size==4
        if not self.readable:
            raise MemoryError('synthetic unreadable control')
        return bytes(self.data[32:36])

    def mem_write(self,address,data):
        self.calls.append(['write',address,data.hex()])
        assert address==0x26000020 and len(data)==4
        if not self.writable:
            raise MemoryError('synthetic unwritable control')
        self.data[32:36]=data


def _observe_case(handlers,arch,name,old,args,memory,**extra):
    result=None
    error=None
    try:
        result=handlers[name](memory,None,args,{})
    except (OverflowError,MemoryError) as failure:
        error=type(failure).__name__
    return dict(architecture=arch,export=name,old=old,arguments=args,result=result,error=error,
        last_error=memory.last_error,new=int.from_bytes(memory.data[32:36],'little'),
        arena_sha256=hashlib.sha256(memory.data).hexdigest(),calls=memory.calls,**extra)


def observe():
    handlers,contracts,source_hash=_handlers()
    observations=[]
    for arch,bits in [('x86',32),('x64',64)]:
        mask=(1<<bits)-1
        values=sorted(set(x&mask for x in (0,1,0x7fffffff,0x80000000,0xffffffff,0x100000000,mask)))
        for name in NAMES:
            argc=contracts['kernel32',name,'function',arch][0]['argc']
            for old in (0,1,0x7fffffff,0x80000000,0xffffffff):
                tails=[[]] if argc==1 else [[v] for v in values] if argc==2 else [
                    [v,c] for v in values for c in sorted(set((0,old,(old+1)&mask,mask)))]
                for tail in tails:
                    observations.append(_observe_case(handlers,arch,name,old,[0x26000020,*tail],Memory(old)))
            for readable,writable in [(False,True),(True,False)]:
                old=0x12345678
                args=[0x26000020]+([1] if argc>=2 else [])+([old] if argc==3 else [])
                case=_observe_case(handlers,arch,name,old,args,Memory(old,readable,writable),
                             synthetic_access=dict(readable=readable,writable=writable))
                assert case['error']=='MemoryError' and case['new']==old
                observations.append(case)
    rows=[dict(module='kernel32',export=name,kind='function',architecture=arch,
               reference_sources=contracts['kernel32',name,'function',arch])
          for arch in ('x86','x64') for name in NAMES]
    return dict(schema=1,scope='Frozen interlocked reference over synthetic memory; memory access failures are synthetic controls, not a claim about legacy exception formatting',source=SOURCE,source_sha256=source_hash,contracts=rows,cases=observations)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'rust/emumee-engine/src/api/interlocked_reference.json')
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    document=observe()
    if args.check:
        assert json.loads(args.output.read_bytes())==document,'Frozen interlocked observations changed'
    else:
        atomic_write(args.output,json.dumps(document,indent=2)+'\n')
    print(json.dumps(dict(contracts=len(document['contracts']),observations=len(document['cases']),checked=args.check)))
