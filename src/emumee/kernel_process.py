"""The initial System process global points to the existing guest object."""
from speakeasy.windows.loaders import ApiModuleLoader
from .kernel_data_exports import add_readonly_exports


class KernelInitialSystemProcess:
    name='PsInitialSystemProcess'

    def __init__(self,kernel):
        self.kernel=kernel
        self.address=None
        self.process_address=None

    def storage(self,_api,pointer=0):
        if self.address is None or pointer and pointer!=self.address:
            raise ValueError('Initial System process data has no initialized provider storage')
        return self.address

    def install(self,handler):
        handler.data[self.name]=self.storage

    def prepare(self,image):
        if image.name!='ntoskrnl' or not isinstance(image.loader,ApiModuleLoader):return None
        process=self.kernel.get_system_process()
        if process is None or process.pid!=4 or not process.address:
            raise ValueError('Initial System process export requires the existing guest System object')
        width=self.kernel.get_ptr_size()
        self.process_address=process.address
        result=add_readonly_exports(image,{self.name:process.address.to_bytes(width,'little')},'.emuproc',width)
        page,addresses=result
        self.address=addresses[self.name]
        self.kernel.data_import_addresses[('ntoskrnl',self.name)]=self.address
        return page

    def report(self):
        return {'name':self.name,'type':'PEPROCESS','address':hex(self.address) if self.address is not None else None,
            'process':hex(self.process_address) if self.process_address is not None else None,
            'pid':4 if self.process_address is not None else None,'permissions':'r--',
            'scope':'Existing modeled System process identity; read-only global pointer; no private EPROCESS layout guarantee or process replacement'}
