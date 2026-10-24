"""Kernel virtual addresses for modeled objects, stacks, and API routines."""

from speakeasy import common
from speakeasy.windows.loaders import ApiModuleLoader
from speakeasy.windows.winemu import _normalize_mod_name


OBJECT_TAGS = frozenset({
    "emu.struct.ETHREAD", "emu.struct.EPROCESS", "emu.struct.TOKEN",
    "emu.struct.DRIVER_OBJECT", "emu.struct.DEVICE_OBJECT", "emu.struct.FILE_OBJECT",
})


class KernelAddressSpace:
    """Keep guest-visible kernel pointers in their modeled system ranges."""

    def mem_map(self, size, base=None, perms=common.PERM_MEM_RWX, tag=None, **kwargs):
        if tag in OBJECT_TAGS or isinstance(tag, str) and tag.startswith("emu.object."):
            # These objects have no user-specified address. The upstream object
            # manager otherwise uses its user-space small-block allocator (and
            # an explicit low address for EPROCESS). Give each object NX pages.
            cursor = getattr(self, "kernel_object_cursor", 0)
            if not cursor:
                cursor = 0xFFFFA10000000000 if self.get_ptr_size() == 8 else 0xD0000000
            base = cursor
            self.kernel_object_cursor = cursor + ((size + 4095) & ~4095)
            if perms == common.PERM_MEM_RWX:
                perms = common.PERM_MEM_RW
        return super().mem_map(size, base=base, perms=perms, tag=tag, **kwargs)

    def get_proc(self, module_name, function_name):
        name = _normalize_mod_name(module_name)
        _, data = self.api.get_data_export_handler(name, function_name)
        if data is not None:
            key = name, function_name
            if key not in self.data_import_addresses:
                self.data_import_addresses[key] = self.handle_import_data(name, function_name)
            return self.data_import_addresses[key]
        for module in getattr(self, "modules", ()):
            if module.name != name or not isinstance(module.loader, ApiModuleLoader):
                continue
            exported = module.get_export_by_name(function_name)
            if exported is None:
                continue
            _, data = self.api.get_data_export_handler(name, function_name)
            if data is None:
                # The CPU hook dispatches symbols, while import diagnostics and
                # routine lookup use the import table. Both must name the same
                # address that is present in the provider's export directory.
                self.import_table[exported.address] = name, function_name
                self.symbols[exported.address] = name, function_name
                if not hasattr(self, "modeled_function_addresses"):
                    self.modeled_function_addresses = set()
                self.modeled_function_addresses.add(exported.address)
                return exported.address
        return super().get_proc(module_name, function_name)

    def bind_code_imports(self, module):
        width = self.get_ptr_size()
        for imported in module._image.imports:
            name = _normalize_mod_name(imported.dll_name)
            _, function = self.api.get_export_func_handler(name, imported.func_name)
            _, data = self.api.get_data_export_handler(name, imported.func_name)
            if function is None or data is not None:
                continue
            address = imported.iat_address
            if not module.base <= address or address + width > module.base + module.image_size:
                from .pe import InvalidSample
                raise InvalidSample("Kernel code import slot lies outside its image")
            pointer = self.get_proc(name, imported.func_name)
            self.mem_write(address, int(pointer).to_bytes(width, "little"))

    def prepare_entry_stack(self):
        if not getattr(self, "kernel_entry_stack", 0):
            base = 0xFFFFA00000000000 if self.get_ptr_size() == 8 else 0xB0000000
            self.kernel_entry_stack = self.mem_map(
                0x10000, base=base, perms=common.PERM_MEM_RW, tag="emu.stack.kernel_entry")
            self.stack_base = self.kernel_entry_stack + 0x10000
            self.reset_stack(self.stack_base)
