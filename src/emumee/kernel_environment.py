"""Kernel time, counters and processor identity on the shared guest persona."""

from speakeasy import common
from speakeasy.winenv import arch
from speakeasy.windows.loaders import ApiModuleLoader

from .kernel_api import require_range
from .kernel_data_exports import add_readonly_exports


class KernelEnvironment:
    def __init__(self, kernel):
        self.kernel = kernel
        persona = kernel.persona_config or {}
        cpu = persona.get("cpu", {})
        self.logical = int(cpu.get("cores", 1)) * int(cpu.get("threads_per_core", 1))
        self.data_page = None
        self.user_limit_page = None
        self.user_probe_page = None
        self.address_boundaries = {}

    def prepare(self, image):
        if image.name != 'ntoskrnl' or not isinstance(image.loader, ApiModuleLoader):
            return None
        if self.address_boundaries:
            raise ValueError('Address boundary globals already placed')
        width = self.kernel.get_ptr_size()
        build = int((self.kernel.persona_config or {}).get('windows_build',22631))
        top = (1 << (47 if build >= 9600 else 43)) if width == 8 else 1 << 31
        values = {'MmHighestUserAddress': top-0x10001,
                  'MmUserProbeAddress': top-0x10000}
        page, addresses = add_readonly_exports(image,
            {name:value.to_bytes(width,'little') for name,value in values.items()}, '.emubnd', width)
        self.user_limit_page = addresses['MmHighestUserAddress']
        self.user_probe_page = addresses['MmUserProbeAddress']
        for name,value in values.items():
            self.kernel.data_import_addresses[('ntoskrnl',name)] = addresses[name]
            self.address_boundaries[name] = {'address':hex(addresses[name]),'value':hex(value),
                'width':width,'type':'PVOID' if name=='MmHighestUserAddress' else 'ULONG_PTR',
                'permissions':'r--'}
        return page

    def boundary_storage(self, name, pointer):
        entry = self.address_boundaries.get(name)
        if entry is None:
            raise ValueError('Address boundary export requires initialized provider storage')
        address = int(entry['address'],0)
        if pointer and pointer != address:
            raise ValueError('Explicit placement of address boundary data is unsupported')
        return address

    def highest_user_address(self, _api, pointer=0):
        """Pointer-sized data, not a callable API or a host-derived address.

        The guest uses the standard x86 2-GB split. x64 uses the 128-TB
        address-space profile from Windows 8.1 onward, or the earlier 8-TB
        profile. The final 64 KiB is reserved in both profiles.
        """
        return self.boundary_storage('MmHighestUserAddress',pointer)

    def user_probe_address(self, _api, pointer=0):
        return self.boundary_storage('MmUserProbeAddress',pointer)

    def report_address_boundaries(self):
        return {'globals':self.address_boundaries,
                'scope':'Pointer-sized user/probe boundaries of the supported guest address-space profile; read-only/NX globals; no system-range or physical-memory model implied'}

    def system_time(self, _api, emu, argv, ctx=None):
        output = int(argv[0])
        require_range(emu, output, 8, True)
        emu.mem_write(output, emu.get_system_time().to_bytes(8, "little"))

    def performance_counter(self, _api, emu, argv, ctx=None):
        frequency = int(argv[0])
        if frequency:
            require_range(emu, frequency, 8, True)
        clock = emu.virtual_clock
        clock._observe()
        if frequency:
            emu.mem_write(frequency, (10_000_000).to_bytes(8, "little"))
        value = (clock.uptime_ms * 10_000 + clock._submillisecond_100ns) & ((1 << 64) - 1)
        if emu.get_ptr_size() == 4:
            emu.reg_write(arch.X86_REG_EDX, value >> 32)
            return value & 0xFFFFFFFF
        return value

    def active_processors(self, _api, _emu, argv, ctx=None):
        group = int(argv[0]) & 0xFFFF
        return self.logical if group == 0xFFFF else max(0, min(64, self.logical - group * 64))

    def current_processor(self, _api, emu, argv, ctx=None):
        output = int(argv[0])
        number = getattr(emu, "processor_id", 0)
        if output:
            require_range(emu, output, 4, True)
            emu.mem_write(output, (number // 64).to_bytes(2, "little") + bytes([number % 64, 0]))
        return number

    def processor_count_data(self, _api, pointer=0):
        emu = self.kernel
        if not pointer:
            if self.data_page is None:
                base = 0xFFFFF80300000000 if emu.get_ptr_size() == 8 else 0x8FFF0000
                self.data_page = emu.mem_map(4096, base=base, perms=common.PERM_MEM_RW,
                                             tag="emu.kernel.persona_data")
            pointer = self.data_page
        require_range(emu, pointer, 1, True)
        emu.mem_write(pointer, bytes([min(64, self.logical)]))
        return pointer

    def install(self, ntos):
        for name, function, count in (("KeQuerySystemTime", self.system_time, 1),
                ("KeQuerySystemTimePrecise", self.system_time, 1),
                ("KeQueryPerformanceCounter", self.performance_counter, 1),
                ("KeQueryActiveProcessorCountEx", self.active_processors, 1),
                ("KeGetCurrentProcessorNumberEx", self.current_processor, 1)):
            ntos.funcs[name] = name, function, count, arch.CALL_CONV_STDCALL, None
        def current_number(api, emu, argv, ctx=None):
            return getattr(emu, "processor_id", 0) % 64
        ntos.funcs["KeGetCurrentProcessorNumber"] = "KeGetCurrentProcessorNumber", current_number, 0, arch.CALL_CONV_STDCALL, None
        ntos.data["KeNumberProcessors"] = self.processor_count_data
        ntos.data["MmHighestUserAddress"] = self.highest_user_address
        ntos.data["MmUserProbeAddress"] = self.user_probe_address
        hal = self.kernel.api.load_api_handler("hal")
        hal.funcs["KeQueryPerformanceCounter"] = ntos.funcs["KeQueryPerformanceCounter"]
        for name in ("KfRaiseIrql", "KfLowerIrql", "KeLowerIrql", "KeGetCurrentIrql"):
            hal.funcs[name] = ntos.funcs[name]
