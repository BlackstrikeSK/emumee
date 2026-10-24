"""Guest kernel debugger data: no debugger transport or attachment is modeled."""
from speakeasy.winenv import arch
from .kernel_api import require_range
from .kernel_data_exports import add_readonly_exports


class KernelDebuggerState:
    values={'KdDebuggerEnabled':0,'KdDebuggerNotPresent':1,'KdEnteredDebugger':0}

    def __init__(self,kernel):
        self.kernel=kernel
        self.addresses={}
        self.prompts=[]
        self.prompt_calls=0

    def prompt(self,_api,emu,argv,ctx=None):
        # DbgPrompt returns the number of received characters. This guest has
        # no debugger transport or input: return zero without writing even a
        # terminator into Response. Never obtain input from the host console.
        prompt,response,length=map(int,argv)
        length &= 0xffffffff
        if length>512:
            raise ValueError('DbgPrompt response exceeds the modeled 512-character bound')
        text=bytearray()
        for offset in range(512):
            require_range(emu,prompt+offset,1)
            value=emu.mem_read(prompt+offset,1)[0]
            if value==0:break
            text.append(value)
        else:
            raise ValueError('DbgPrompt prompt is not terminated within 512 bytes')
        if length:require_range(emu,response,length,True)
        self.prompt_calls+=1
        if len(self.prompts)<64:
            self.prompts.append({'prompt':text.decode('latin1'),
                'prompt_address':hex(prompt),'response_address':hex(response),
                'length':length,'received_characters':0})
        return 0

    def storage(self,name,pointer=0):
        address=self.addresses.get(name)
        if address is None or pointer and pointer!=address:
            raise ValueError('Guest debugger data has no initialized provider storage')
        return address

    def install(self,handler):
        for name in self.values:
            handler.data[name]=lambda api,pointer=0,name=name:self.storage(name,pointer)
        handler.funcs['DbgPrompt']=('DbgPrompt',self.prompt,3,arch.CALL_CONV_STDCALL,None)

    def prepare(self,image):
        result=add_readonly_exports(image,{name:bytes([value]) for name,value in self.values.items()},'.emukd')
        if result is None:return None
        page,self.addresses=result
        for name,address in self.addresses.items():self.kernel.data_import_addresses[('ntoskrnl',name)]=address
        return page

    def report(self):
        return {'enabled':False,'not_present':True,'entered':False,
                'exports':{name:{'address':hex(self.addresses[name]),'value':value}
                           for name,value in self.values.items() if name in self.addresses},
                'permissions':'r--',
                'prompt':{'calls':self.prompt_calls,'observations':self.prompts,
                    'omitted':self.prompt_calls-len(self.prompts),
                    'input_policy':'no_input','response_writes':0,
                    'scope':'DbgPrompt receives no characters and leaves Response unchanged; prompt including NUL and response capacity are bounded to 512 bytes. No host console or debugger interaction.'},
                'scope':'Guest kernel debugger disabled; no guest debugger transport, attachment, refresh or state mutation is implemented; state is not discovered from the host'}
