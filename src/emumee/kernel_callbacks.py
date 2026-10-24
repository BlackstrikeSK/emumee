"""Guest bookkeeping for documented bug-check reason registrations.

The WDK's opaque record layout is populated for registration/deregistration.
No bug check is synthesized, and crash-time callback dispatch is not implemented.
Internal Windows checksum behavior is not modeled.
"""

from .kernel_api import guest_range, require_range


class KernelBugcheckCallbacks:
    def __init__(self, kernel):
        self.kernel = kernel
        self.active = {}

    def _layout(self):
        width = self.kernel.get_ptr_size()
        return width, width * 5 + 4, 48 if width == 8 else 28

    def _links(self):
        emu = self.kernel
        width, _state, _size = self._layout()
        head = emu.kernel_lock_storage + 0x100
        nodes = [head, *self.active]
        for index, address in enumerate(nodes):
            require_range(emu, address, width * 2, True)
            emu.mem_write(address, nodes[(index + 1) % len(nodes)].to_bytes(width, "little")
                          + nodes[(index - 1) % len(nodes)].to_bytes(width, "little"))

    def register(self, _handler, emu, argv, ctx=None):
        record, routine, reason, component = map(int, argv)
        reason &= 0xFFFFFFFF
        width, state, size = self._layout()
        require_range(emu, record, size)
        require_range(emu, record, size, True)
        if record in self.active or emu.mem_read(record + state, 1) != b"\0":
            return 0
        if reason not in range(2, 8) or not guest_range(emu, routine, 1, 4):
            return 0
        label = bytearray()
        for offset in range(256):
            require_range(emu, component + offset, 1)
            value = emu.mem_read(component + offset, 1)
            if value == b"\0":
                break
            label += value
        else:
            emu.lifecycle_errors.append("Bug-check component exceeds the modeled 255-byte limit")
            return 0
        if len(self.active) >= 256:
            emu.lifecycle_errors.append("Bug-check callback registration limit exceeded")
            return 0
        emu.mem_write(record + width * 2, routine.to_bytes(width, "little"))
        emu.mem_write(record + width * 3, component.to_bytes(width, "little"))
        emu.mem_write(record + width * 5, reason.to_bytes(4, "little") + b"\1")
        self.active[record] = {"record": hex(record), "routine": hex(routine),
            "reason": reason, "component": label.decode("ascii", errors="replace")}
        self._links()
        return 1

    def deregister(self, _handler, emu, argv, ctx=None):
        record = int(argv[0])
        _width, state, size = self._layout()
        require_range(emu, record, size)
        if record not in self.active:
            return 0
        require_range(emu, record, size, True)
        del self.active[record]
        emu.mem_write(record + state, b"\0")
        self._links()
        return 1

    def report(self):
        return {"registered": list(self.active.values()), "callbacks_executed": 0,
                "scope": "Registration bookkeeping; crash callback dispatch and internal checksums are not modeled"}

    def install(self, handler):
        from speakeasy.winenv import arch
        for name, function, count in (("KeRegisterBugCheckReasonCallback", self.register, 4),
                ("KeDeregisterBugCheckReasonCallback", self.deregister, 1)):
            handler.funcs[name] = name, function, count, arch.CALL_CONV_STDCALL, None
