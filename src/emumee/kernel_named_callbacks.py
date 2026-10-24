"""Named executive callback objects; notification dispatch is explicit unsupported.

Contracts: Microsoft WDK ExCreateCallback, ExRegisterCallback,
ExUnregisterCallback and ExNotifyCallback. No system event is synthesized.
"""
from speakeasy import common
from speakeasy.windows.objman import KernelObject
from speakeasy.winenv import arch
from .kernel_api import require_range, guest_range


class CallbackObject(KernelObject):
    def __init__(self, emu, name, multiple, permanent, system):
        super().__init__(emu)
        self.name, self.multiple = name, multiple
        self.permanent, self.system = permanent, system
        self.address = emu.mem_map(4096, perms=common.PERM_MEM_NONE,
                                   tag='emu.object.callback')

    def get_class_name(self):
        return 'CALLBACK_OBJECT'


class KernelNamedCallbacks:
    SYSTEM_NAMES = (r'\Callback\SetSystemTime', r'\Callback\PowerState',
                    r'\Callback\ProcessorAdd')

    def __init__(self, kernel):
        self.kernel = kernel
        self.objects = []
        self.registrations = {}
        self.events = []
        self.omitted = 0
        self.api_denials = []

    def event(self, operation, **values):
        if len(self.events) < 256:
            self.events.append(dict(operation=operation, **values))
        else:
            self.omitted += 1

    def irql(self, maximum):
        if self.kernel.get_current_irql() > maximum:
            raise ValueError('Named callback operation above its supported IRQL')

    def object(self, address):
        obj = self.kernel.get_object_from_addr(address)
        if not isinstance(obj, CallbackObject) or obj.ref_cnt <= 0:
            raise ValueError('Named callback requires a live CALLBACK_OBJECT')
        return obj

    def create(self, handler, emu, argv, ctx=None):
        self.irql(1)
        output, attributes, create, multiple = map(int, argv)
        width = emu.get_ptr_size()
        require_range(emu, output, width, True)
        size = 48 if width == 8 else 24
        require_range(emu, attributes, size)
        oa = handler.mem_cast(handler.win.OBJECT_ATTRIBUTES(width), attributes)
        if oa.Length != size:
            return 0xC000000D
        if oa.RootDirectory or oa.SecurityDescriptor or oa.SecurityQualityOfService:
            raise ValueError('Callback root handles and security descriptors are not modeled')
        if oa.Attributes & ~(0x10 | 0x40 | 0x80 | 0x200):
            raise ValueError('Unsupported callback object attributes')
        if not oa.ObjectName:
            return 0xC0000001  # WDK: unnamed callback objects are not permitted.
        require_range(emu, oa.ObjectName, 16 if width == 8 else 8)
        us = handler.mem_cast(handler.win.UNICODE_STRING(width), oa.ObjectName)
        if us.Length % 2 or us.Length > us.MaximumLength or us.Length > 32766:
            return 0xC000000D
        if not us.Length:
            return 0xC0000001
        require_range(emu, us.Buffer, us.Length)
        try:
            name = emu.mem_read(us.Buffer, us.Length).decode('utf-16le')
        except UnicodeError:
            return 0xC0000033
        if '\0' in name or not name.startswith('\\') or name.endswith('\\'):
            return 0xC0000033
        if name[:10].casefold() != '\\callback\\' or '\\' in name[10:]:
            raise ValueError('Only absolute names in the Callback directory are modeled')
        insensitive = bool(oa.Attributes & 0x40)
        equal = lambda other: other.casefold() == name.casefold() if insensitive else other == name
        obj = next((o for o in emu.om.objects.values() if o.name and equal(o.name)), None)
        if obj is not None and not isinstance(obj, CallbackObject):
            return 0xC0000024
        system_name = next((n for n in self.SYSTEM_NAMES if equal(n)), None)
        created = obj is None
        if obj is None:
            if system_name is None and not create & 0xFF:
                return 0xC0000034
            if len(self.objects) >= 256:
                return 0xC000009A
            obj = CallbackObject(emu, system_name or name, True if system_name else bool(multiple & 0xFF),
                                 bool(system_name or oa.Attributes & 0x10), bool(system_name))
            emu.add_object(obj)  # Caller reference.
            if obj.permanent:
                obj.ref_cnt += 1  # Namespace/system lifetime.
            self.objects.append(obj)
        else:
            obj.ref_cnt += 1
        emu.mem_write(output, obj.address.to_bytes(width, 'little'))
        self.event('open' if system_name or not created else 'create', object=hex(obj.address),
                   name=obj.name, references_after=obj.ref_cnt)
        return 0

    def register(self, handler, emu, argv, ctx=None):
        self.irql(1)
        address, routine, context = map(int, argv)
        obj = self.object(address)
        active = [r for r in self.registrations.values() if r['active'] and r['object'] is obj]
        if not obj.multiple and active:
            return 0
        if not guest_range(emu, routine, 1, 4) or len(self.registrations) >= 256:
            return 0
        token = emu.mem_map(4096, perms=common.PERM_MEM_NONE, tag='emu.object.callback_registration')
        self.registrations[token] = dict(object=obj, routine=routine, context=context, active=True)
        obj.ref_cnt += 1
        self.event('register', object=hex(address), token=hex(token), references_after=obj.ref_cnt)
        return token

    def unregister(self, handler, emu, argv, ctx=None):
        self.irql(1)
        token = int(argv[0])
        row = self.registrations.get(token)
        if row is None or not row['active']:
            raise ValueError('Invalid or inactive callback registration')
        row['active'] = False
        obj = row['object']
        emu.om.dec_ref(obj)
        self.event('unregister', object=hex(obj.address), token=hex(token), references_after=obj.ref_cnt)

    def notify(self, handler, emu, argv, ctx=None):
        self.irql(2)
        address, first, second = map(int, argv)
        obj = self.object(address)
        if obj.system:
            raise ValueError('Drivers must not notify system-defined callback objects')
        active = [r for r in self.registrations.values() if r['active'] and r['object'] is obj]
        self.event('notify', object=hex(address), argument1=hex(first), argument2=hex(second),
                   registered=len(active), dispatched=0)
        if active:
            raise ValueError('ExNotifyCallback dispatch of registered guest routines is not modeled')

    def require_api_access(self, address, size, access):
        if size <= 0:
            return
        regions = [(o.address, 'CALLBACK_OBJECT') for o in self.objects]
        regions += [(token, 'CALLBACK_REGISTRATION') for token in self.registrations]
        for base, kind in regions:
            if address < base + 4096 and address + size > base:
                if len(self.api_denials) < 64:
                    self.api_denials.append(dict(kind=kind, offset=address-base, access=access, size=size))
                raise ValueError(f'Unmodeled private {kind} {access} at offset {address-base:#x}')

    def install(self, handler):
        for name, function, count in (('ExCreateCallback', self.create, 4),
                ('ExRegisterCallback', self.register, 3), ('ExUnregisterCallback', self.unregister, 1),
                ('ExNotifyCallback', self.notify, 3)):
            handler.funcs[name] = name, function, count, arch.CALL_CONV_STDCALL, None

    def report(self):
        return {'objects':[dict(address=hex(o.address), name=o.name, allow_multiple=o.multiple,
                    permanent=o.permanent, system=o.system, references=o.ref_cnt,
                    live=self.kernel.get_object_from_addr(o.address) is o,
                    permissions='---') for o in self.objects],
                'registrations':[dict(token=hex(token), object=hex(r['object'].address),
                    routine=hex(r['routine']), context=hex(r['context']), active=r['active'])
                    for token,r in self.registrations.items()],
                'events':self.events, 'omitted':self.omitted, 'api_denials':self.api_denials,
                'callbacks_executed':0,
                'scope':'Named Callback-directory create/open and object-manager lifetimes; register/unregister; empty notifications only; registered notification dispatch stops explicitly; no synthesized system events or private object layout'}
