"""Kernel object-type identities and real object-manager reference lifetimes."""

from speakeasy import common
from speakeasy.windows.objman import Thread, Process, Driver, FileObject, Event, Token
from speakeasy.windows.loaders import ApiModuleLoader
from speakeasy.winenv import arch

from .kernel_api import require_range
from .kernel_data_exports import add_readonly_exports

TYPE_EXPORTS = {'PsThreadType': 'Thread', 'PsProcessType': 'Process',
                'IoDriverObjectType': 'Driver', 'IoFileObjectType': 'File',
                'MmSectionObjectType': 'Section', 'ExEventObjectType': 'Event',
                'ExSemaphoreObjectType': 'Semaphore', 'SeTokenObjectType': 'Token',
                'TmEnlistmentObjectType': 'TmEnlistment',
                'TmResourceManagerObjectType': 'TmResourceManager',
                'TmTransactionManagerObjectType': 'TmTransactionManager',
                'TmTransactionObjectType': 'TmTransaction'}


class KernelReferences:
    def __init__(self, kernel):
        self.kernel = kernel
        self.types = {}
        self.events = []
        self.omitted = 0

    def prepare(self, image):
        if image.name != 'ntoskrnl' or not isinstance(image.loader, ApiModuleLoader):
            return None
        if self.types:
            raise ValueError('Object types already placed before provider preparation')
        width = self.kernel.get_ptr_size()
        values = {}
        for export, name in TYPE_EXPORTS.items():
            identity = self.kernel.mem_map(4096, perms=common.PERM_MEM_NONE,
                                           tag=f'emu.object.type.{name}')
            self.types[name] = {'identity': identity}
            values[export] = identity.to_bytes(width, 'little')
        page, addresses = add_readonly_exports(image, values, '.emutype', width)
        for export, name in TYPE_EXPORTS.items():
            storage = addresses[export]
            self.types[name]['storage'] = storage
            self.kernel.data_import_addresses[('ntoskrnl', export)] = storage
        return page

    def exported_type(self, name, pointer=0):
        # OBJECT_TYPE is opaque: its identity can be compared/passed to an API,
        # but unmodeled internal fields must not read as fabricated zeros.
        if name not in self.types or 'storage' not in self.types[name]:
            raise ValueError('Object type export requires initialized provider storage')
        result = self.types[name]
        if pointer and pointer != result["storage"]:
            raise ValueError("Explicit placement of an opaque object-type export is unsupported")
        return result["storage"]

    def identity(self, obj):
        name = next((name for cls, name in ((Thread,'Thread'), (Process,'Process'),
                    (Driver,'Driver'), (FileObject,'File'), (Event,'Event'),
                    (Token,'Token')) if isinstance(obj,cls)), None)
        if name is None:
            return None
        self.exported_type(name)
        return self.types[name]["identity"]

    def object(self, address):
        obj = self.kernel.get_object_from_addr(address)
        if obj is None or obj.ref_cnt <= 0:
            raise ValueError("Object reference requires a live modeled object body")
        return obj

    def record(self, operation, obj):
        if len(self.events) < 128:
            self.events.append({"operation": operation, "object": hex(obj.address),
                                "kind": obj.get_class_name(), "references_after": obj.ref_cnt})
        else:
            self.omitted += 1

    def by_pointer(self, api, emu, argv, ctx=None):
        address, access, object_type, mode = map(int, argv)
        if emu.get_current_irql() > 2:
            raise ValueError("Object reference above DISPATCH_LEVEL")
        obj = self.object(address)
        mode &= 0xFF
        if mode == 1:
            expected = self.identity(obj)
            if expected is not None and object_type and object_type != expected:
                return 0xC0000024
            raise ValueError("User-mode object security/access validation is not modeled")
        if mode != 0:
            raise ValueError("Unsupported object reference access mode")
        # WDK: ObReferenceObjectByPointer does not require a type match for a
        # KernelMode caller. ObReferenceObjectByHandle below does validate it.
        obj.ref_cnt += 1
        self.record("reference_by_pointer", obj)
        return 0

    def by_handle(self, api, emu, argv, ctx=None):
        handle, access, object_type, mode, output, information = map(int, argv)
        if emu.get_current_irql():
            raise ValueError("ObReferenceObjectByHandle requires PASSIVE_LEVEL")
        obj = emu.get_object_from_handle(handle)
        if obj is None or obj.ref_cnt <= 0:
            return 0xC0000008
        if object_type:
            expected = self.identity(obj)
            if expected is None:
                if any(object_type == entry["identity"] for entry in self.types.values()):
                    return 0xC0000024
                raise ValueError("Object type identity is not modeled for this handle")
            if object_type != expected:
                return 0xC0000024
        if mode & 0xFF:
            raise ValueError("User-mode handle security/access validation is not modeled")
        if information:
            raise ValueError("Object handle-information output is not modeled")
        require_range(emu, output, emu.get_ptr_size(), True)
        emu.mem_write(output, obj.address.to_bytes(emu.get_ptr_size(), "little"))
        obj.ref_cnt += 1
        self.record("reference_by_handle", obj)
        return 0

    def reference(self, api, emu, argv, ctx=None):
        if emu.get_current_irql() > 2:
            raise ValueError("Object reference above DISPATCH_LEVEL")
        obj = self.object(int(argv[0]))
        obj.ref_cnt += 1
        self.record("reference", obj)
        return obj.ref_cnt

    def dereference(self, api, emu, argv, ctx=None):
        if emu.get_current_irql() > 2:
            raise ValueError("Object dereference above DISPATCH_LEVEL")
        obj = self.object(int(argv[0]))
        emu.om.dec_ref(obj)
        if obj.ref_cnt <= 0 and isinstance(obj, Thread):
            emu.dispatcher.objects.pop(obj.address, None)
        self.record("dereference", obj)
        return obj.ref_cnt

    def install(self, handler):
        for export, name in TYPE_EXPORTS.items():
            handler.data[export] = lambda api, pointer=0, name=name: self.exported_type(name, pointer)
        for name, function, count, convention in (
                ("ObReferenceObjectByPointer", self.by_pointer, 4, arch.CALL_CONV_STDCALL),
                ("ObReferenceObjectByHandle", self.by_handle, 6, arch.CALL_CONV_STDCALL),
                ("ObfReferenceObject", self.reference, 1, arch.CALL_CONV_FASTCALL),
                ("ObReferenceObject", self.reference, 1, arch.CALL_CONV_FASTCALL),
                ("ObfDereferenceObject", self.dereference, 1, arch.CALL_CONV_FASTCALL),
                ("ObDereferenceObject", self.dereference, 1, arch.CALL_CONV_FASTCALL)):
            handler.funcs[name] = name, function, count, convention, None

    def report(self):
        return {"types": {name: {key: hex(value) for key, value in item.items()}
                          for name, item in self.types.items()},
                "events": self.events, "omitted": self.omitted,
                "scope": "Opaque kernel object-type identities; modeled object reference counts; "
                         "KernelMode pointer/handle references; no UserMode ACL checks or OBJECT_TYPE internals"}
