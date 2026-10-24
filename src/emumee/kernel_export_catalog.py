"""Native export-name metadata with protected, unimplemented operations."""
import struct
import pefile
from speakeasy.common import PERM_MEM_NONE
from speakeasy.windows.loaders import ApiModuleLoader,SectionEntry
from speakeasy.winenv import arch
from .kernel_export_names_22631 import (CODE_EXPORTS,DATA_EXPORTS,SOURCE_SHA256,
    SOURCE_URL,SOURCE_FILE_VERSION,CATALOG_METADATA_SHA256)


class KernelExportCatalog:
    PAGE_SIZE=4096

    def __init__(self,kernel):
        self.kernel=kernel
        self.enabled=kernel.get_ptr_size()==8 and int((kernel.persona_config or {}).get('windows_build',22631))==22631
        self.unknown={}
        self.addresses={}
        self.names=[]
        self.base=None
        self.size=0
        self.denials=[]
        self.omitted=0
        self.reference_code_addresses={}

    def record(self,item,access,address,size):
        if len(self.denials)<64:
            self.denials.append(dict(item,access=access,address=hex(address),size=size))
        else:
            self.omitted+=1

    def install(self,handler):
        if not self.enabled:return
        if len(CODE_EXPORTS)!=3180 or len(DATA_EXPORTS)!=77 or len(set(CODE_EXPORTS+DATA_EXPORTS))!=3257:
            raise ValueError('Invalid pinned kernel export-name catalog')
        for kind,names in (('code',CODE_EXPORTS),('data',DATA_EXPORTS)):
            for name in names:
                if name in handler.funcs or name in handler.data:continue
                self.unknown[name]=kind
                if kind=='code':
                    def unsupported(api,emu,argv,ctx=None,name=name):
                        item={'name':name,'kind':'code','offset':0}
                        self.record(item,'api_dispatch',self.addresses.get(name,0),0)
                        raise ValueError('Unimplemented catalog API '+name+'; argument contract is not modeled')
                    handler.funcs[name]=(name,unsupported,0,arch.CALL_CONV_STDCALL,None)
                else:
                    handler.data[name]=lambda api,pointer=0,name=name:self.storage(name,pointer)

    def storage(self,name,pointer):
        address=self.addresses.get(name)
        if address is None or pointer and pointer!=address:
            raise ValueError('Kernel catalog metadata has no initialized provider address')
        return address

    def prepare(self,image):
        if not self.enabled or image.name!='ntoskrnl' or not isinstance(image.loader,ApiModuleLoader):return None
        if self.base is not None:raise ValueError('Kernel export metadata already placed')
        data=bytearray(image.regions[0].data)
        pe=pefile.PE(data=bytes(data),fast_load=True)
        rva=(max(image.image_size,len(data))+4095)&~4095
        self.size=len(self.unknown)*4096
        # System modules normally use16 MiB, or32 MiB with an inspection view.
        # This metadata must not
        # overlap the next provider or exhaust the bounded PE section layout.
        if not 0<self.size<=15*1024*1024 or rva+self.size>=getattr(self.kernel,'kernel_provider_spacing',16*1024*1024):
            raise ValueError('Kernel export metadata exceeds its provider reservation')
        header=pe.sections[-1].get_file_offset()+40
        if header+40>min(s.VirtualAddress for s in pe.sections):
            raise ValueError('Kernel export metadata has no PE header space')
        data.extend(bytes(rva+self.size-len(data)))
        struct.pack_into('<8sIIIIIIHHI',data,header,b'.unmodel',self.size,rva,self.size,rva,0,0,0,0,0x40)
        struct.pack_into('<H',data,pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),pe.FILE_HEADER.NumberOfSections+1)
        struct.pack_into('<I',data,pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),rva+self.size)
        alignment=pe.OPTIONAL_HEADER.FileAlignment
        struct.pack_into('<I',data,pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfHeaders'),
            max(pe.OPTIONAL_HEADER.SizeOfHeaders,(header+40+alignment-1)//alignment*alignment))
        export_rva=pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
        ordinal_base,count,names=struct.unpack_from('<III',data,export_rva+16)
        functions_rva,names_rva,ordinals_rva=struct.unpack_from('<III',data,export_rva+28)
        entries=[]
        for index in range(names):
            name_rva=struct.unpack_from('<I',data,names_rva+4*index)[0]
            end=data.find(b'\0',name_rva)
            ordinal=struct.unpack_from('<H',data,ordinals_rva+2*index)[0]
            if end<name_rva or ordinal>=count:
                raise ValueError('Invalid generated kernel export-name index')
            entries.append((bytes(data[name_rva:end]),name_rva,ordinal))
        for index,(_,name_rva,ordinal) in enumerate(sorted(entries)):
            struct.pack_into('<I',data,names_rva+4*index,name_rva)
            struct.pack_into('<H',data,ordinals_rva+2*index,ordinal)
        exported={item.name:item for item in image.exports}
        self.names=sorted(self.unknown)
        for index,name in enumerate(self.names):
            item=exported[name];ordinal=item.ordinal-ordinal_base
            if not 0<=ordinal<count:raise ValueError('Invalid generated kernel catalog ordinal')
            address_rva=rva+index*4096
            reference=getattr(self.kernel,'kernel_code_reference',None)
            if (self.unknown[name]=='code' and reference is not None and
                    reference.base==image.image_base and name in reference.code_exports):
                # These are inspection-only functions: retain their genuine
                # reference RVAs rather than making a protected placeholder
                # look like their code. Their implementations remain absent.
                address_rva=reference.code_exports[name]
                self.reference_code_addresses[name]=image.image_base+address_rva
            struct.pack_into('<I',data,functions_rva+4*ordinal,address_rva)
            item.address=image.image_base+address_rva
            item.execution_mode='native'
            self.addresses[name]=item.address
            if self.unknown[name]=='data':
                self.kernel.data_import_addresses[('ntoskrnl',name)]=item.address
        self.base=image.image_base+rva
        image.image_size=rva+self.size
        image.regions[0].data=bytes(data)
        image.sections.append(SectionEntry('.unmodel',rva,self.size,PERM_MEM_NONE))
        return self.base,self.size

    def describe(self,address,size=1):
        if self.base is None or size<=0 or address>=self.base+self.size or address+size<=self.base:return None
        index=(max(address,self.base)-self.base)//4096
        name=self.names[index];base=self.base+index*4096
        return {'name':name,'kind':self.unknown[name],'offset':address-base}

    def require_api_access(self,address,size,access):
        item=self.describe(address,size)
        if item is None:return
        self.record(item,access,address,size)
        raise ValueError(f"Unmodeled catalog symbol {item['name']} {access} at offset {item['offset']:#x}")

    def report(self):
        return {'enabled':self.enabled,'guest_profile':'x64 Windows11 build22631',
            'source_file_version':SOURCE_FILE_VERSION,'source_image_sha256':SOURCE_SHA256,
            'source_url':SOURCE_URL,'catalog_metadata_sha256':CATALOG_METADATA_SHA256,
            'named_reference_exports':3257,'reference_code_symbols':3180,'reference_data_symbols':77,
            'metadata_only_added':len(self.unknown),
            'code_metadata_added':sum(k=='code' for k in self.unknown.values()),
            'data_metadata_added':sum(k=='data' for k in self.unknown.values()),
            'address':hex(self.base) if self.base is not None else None,'size':self.size,
            'symbol_page_size':4096,'permissions':'---','denials':self.denials,'omitted':self.omitted,
            'reference_code_exports':len(self.reference_code_addresses),
            'reference_code_policy':'When available, unimplemented code exports point to file-backed reference code at its original RVA (read-only/NX). Implemented APIs retain generated stubs; data exports retain modeled storage or protected placeholders.',
            'scope':'Export names/classifications from an authenticated shared 22H2/23H2 reference; generated ordinals. Protected placeholders stop calls/function-byte/data accesses explicitly. Optional reference code addresses supply inspection bytes only; no implementation, private values or boot state.'}
