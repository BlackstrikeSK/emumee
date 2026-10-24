"""Known kernel data symbols whose private contents are not modeled."""
import struct
import pefile
from speakeasy.windows.loaders import ApiModuleLoader
from .kernel_data_exports import add_readonly_exports


class KernelOpaqueData:
    name='HalPrivateDispatchTable'

    def __init__(self,kernel):
        self.kernel=kernel
        self.address=None
        self.api_denials=[]
        self.omitted=0

    def install(self,handler):
        handler.data[self.name]=self.storage

    def storage(self,_api,pointer=0):
        if self.address is None or pointer and pointer!=self.address:
            raise ValueError('Opaque kernel data has no initialized provider storage')
        return self.address

    def prepare(self,image):
        if image.name!='ntoskrnl' or not isinstance(image.loader,ApiModuleLoader):return None
        if self.address is not None:raise ValueError('Opaque kernel data already placed')
        page,addresses=add_readonly_exports(image,{self.name:b'UNMODELED'},'.emuopaq',self.kernel.get_ptr_size())
        data=bytearray(image.regions[0].data)
        pe=pefile.PE(data=bytes(data),fast_load=True)
        struct.pack_into('<I',data,pe.sections[-1].get_file_offset()+36,0x40)
        image.regions[0].data=bytes(data)
        image.sections[-1].perms=0
        self.address=addresses[self.name]
        self.kernel.data_import_addresses[('ntoskrnl',self.name)]=self.address
        return page

    def describe(self,address,size=1):
        if self.address is not None and size>0 and address<self.address+4096 and address+size>self.address:
            return {'name':self.name,'offset':address-self.address}
        return None

    def require_api_access(self,address,size,access):
        item=self.describe(address,size)
        if item is None:return
        if len(self.api_denials)<64:
            self.api_denials.append(dict(item,address=hex(address),size=size,access=access))
        else:self.omitted+=1
        raise ValueError(f"Unmodeled kernel data {self.name} {access} at offset {item['offset']:#x}")

    def report(self):
        return {'name':self.name,'type':'HAL_PRIVATE_DISPATCH',
            'address':hex(self.address) if self.address is not None else None,
            'reserved_size':4096,'permissions':'---','layout_version':None,
            'field_values_exposed':False,'api_denials':self.api_denials,'omitted':self.omitted,
            'scope':'Symbol address metadata only; private table fields and HAL callbacks unimplemented; native accesses and API memory reads/writes stop explicitly'}
