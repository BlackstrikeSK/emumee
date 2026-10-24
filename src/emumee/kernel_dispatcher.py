"""Kernel event, timer and current-thread wait state; callbacks require scheduling."""

import struct
from speakeasy.winenv import arch
from .kernel_api import require_range, guest_range


class KernelDispatcher:
    """Event and timer state with explicit failure for waits needing scheduling."""

    def __init__(self, kernel):
        self.kernel = kernel
        self.objects = {}
        self.dpcs = {}
        self.timer_hooks = set()

    def header(self, emu, address, kind, size, signal=0):
        if address not in self.objects and len(self.objects) >= 4096:
            raise ValueError("Kernel dispatcher object limit exceeded")
        require_range(emu, address, size, True)
        width = emu.get_ptr_size()
        blob = bytearray(size)
        blob[0] = kind
        blob[2] = size // 4
        struct.pack_into("<i", blob, 4, signal)
        head = address + 8
        blob[8:8 + 2 * width] = head.to_bytes(width, "little") * 2
        emu.mem_write(address, bytes(blob))

    def object(self, emu, address, kinds=None):
        item = self.objects.get(address)
        if item is None or kinds is not None and item["kind"] not in kinds:
            raise ValueError("Unsupported or uninitialized kernel dispatcher object")
        require_range(emu, address, item["size"])
        return item

    def signal(self, emu, address, value):
        require_range(emu, address + 4, 4, True)
        emu.mem_write(address + 4, struct.pack("<i", value))

    def read_signal(self, emu, address):
        require_range(emu, address + 4, 4)
        return int.from_bytes(emu.mem_read(address + 4, 4), "little", signed=True)

    def initialize_event(self, api, emu, argv, ctx=None):
        address, kind, state = map(int, argv)
        kind &= 0xFFFFFFFF
        if kind not in (0, 1):
            raise ValueError("Invalid kernel event type")
        size = 24 if emu.get_ptr_size() == 8 else 16
        self.header(emu, address, kind, size, int(bool(state & 0xFF)))
        self.objects[address] = {"kind": kind, "size": size}

    def event(self, operation, emu, argv):
        address = int(argv[0])
        self.object(emu, address, (0, 1))
        previous = self.read_signal(emu, address)
        if operation != "read":
            if emu.get_current_irql() > 2:
                raise ValueError("Kernel event operation above DISPATCH_LEVEL")
            if operation == "set" and int(argv[2]) & 0xFF:
                raise ValueError("KeSetEvent Wait=TRUE requires atomic kernel wait scheduling")
            self.signal(emu, address, int(operation == "set"))
        return previous if operation != "clear" else None

    def initialize_timer(self, api, emu, argv, ctx=None):
        address = int(argv[0])
        kind = int(argv[1]) & 0xFFFFFFFF if len(argv) > 1 else 0
        if kind not in (0, 1):
            raise ValueError("Invalid kernel timer type")
        existing = self.objects.get(address)
        if existing is not None and existing.get("inserted"):
            raise ValueError("Reinitializing an inserted kernel timer")
        size = 64 if emu.get_ptr_size() == 8 else 40
        self.header(emu, address, 8 + kind, size)
        self.objects[address] = {"kind": 8 + kind, "size": size, "inserted": False,
                                 "due": 0, "period": 0, "dpc": 0}
        if address not in self.timer_hooks:
            emu.add_mem_read_hook(self.observe_timer_read, begin=address, end=address + size - 1)
            self.timer_hooks.add(address)

    def observe_timer_read(self, emu, access, address, size, value):
        try:
            emu.cpu_model.flush_cycles()
            self.refresh(emu)
        except Exception as error:
            info = emu.get_error_info("kernel_timer_scheduling", address, access_type="read")
            emu.curr_run.error = info.model_copy(update={"context_summary": str(error)[:512]})
            emu.on_emu_complete()
            return False
        return True

    def initialize_dpc(self, api, emu, argv, ctx=None):
        address, routine, context = map(int, argv)
        width = emu.get_ptr_size()
        size = 64 if width == 8 else 32
        require_range(emu, address, size, True)
        if not guest_range(emu, routine, 1, 4):
            raise ValueError("Kernel DPC routine is not executable")
        if address not in self.dpcs and len(self.dpcs) >= 4096:
            raise ValueError("Kernel DPC object limit exceeded")
        blob = bytearray(size)
        blob[0:2] = b"\x13\x01"
        offset = 24 if width == 8 else 12
        blob[offset:offset + width] = routine.to_bytes(width, "little")
        blob[offset + width:offset + width * 2] = context.to_bytes(width, "little")
        emu.mem_write(address, bytes(blob))
        self.dpcs[address] = {"routine": routine, "context": context}

    def interrupt_time(self, emu):
        clock = emu.virtual_clock
        return clock.uptime_ms * 10000 + clock._submillisecond_100ns

    def timer_arguments(self, emu, argv, extended):
        if emu.get_ptr_size() == 4:
            due = (int(argv[1]) & 0xFFFFFFFF) | ((int(argv[2]) & 0xFFFFFFFF) << 32)
            period, dpc = (int(argv[3]), int(argv[4])) if extended else (0, int(argv[3]))
        else:
            due = int(argv[1]) & ((1 << 64) - 1)
            period, dpc = (int(argv[2]), int(argv[3])) if extended else (0, int(argv[2]))
        return (due - (1 << 64) if due >> 63 else due), period & 0xFFFFFFFF, dpc

    def set_timer(self, extended, emu, argv):
        address = int(argv[0])
        item = self.object(emu, address, (8, 9))
        due, period, dpc = self.timer_arguments(emu, argv, extended)
        if period > 0x7FFFFFFF:
            raise ValueError("Negative kernel timer period")
        if dpc:
            require_range(emu, dpc, 64 if emu.get_ptr_size() == 8 else 32)
            if dpc not in self.dpcs:
                raise ValueError("Kernel timer refers to an uninitialized DPC")
        clock = emu.virtual_clock
        clock._observe()
        self.refresh(emu)
        previous = item["inserted"]
        delta = -due if due < 0 else max(0, due - clock.filetime_ticks())
        item.update(inserted=True, due=self.interrupt_time(emu) + delta, period=period, dpc=dpc)
        self.signal(emu, address, 0)
        header = 24 if emu.get_ptr_size() == 8 else 16
        dpc_offset = 48 if emu.get_ptr_size() == 8 else 32
        require_range(emu, address, item["size"], True)
        emu.mem_write(address + 1, bytes([int(due >= 0)]))
        emu.mem_write(address + 3, b"\x40")  # TimerMiscFlags.Inserted
        emu.mem_write(address + header, (item["due"] & ((1 << 64) - 1)).to_bytes(8, "little"))
        emu.mem_write(address + dpc_offset, dpc.to_bytes(emu.get_ptr_size(), "little"))
        emu.mem_write(address + item["size"] - 4, period.to_bytes(4, "little"))
        self.refresh(emu)
        return int(previous)

    def cancel_timer(self, api, emu, argv, ctx=None):
        address = int(argv[0])
        item = self.object(emu, address, (8, 9))
        emu.virtual_clock._observe()
        self.refresh(emu)
        previous = item["inserted"]
        item["inserted"] = False
        require_range(emu, address + 3, 1, True)
        emu.mem_write(address + 3, b"\0")
        return int(previous)

    def refresh(self, emu):
        now = self.interrupt_time(emu)
        for address, item in self.objects.items():
            if item["kind"] not in (8, 9) or not item["inserted"] or item["due"] > now:
                continue
            if item["dpc"]:
                raise ValueError("Due kernel timer DPC requires kernel callback scheduling")
            self.signal(emu, address, 1)
            if item["period"]:
                period = item["period"] * 10000
                item["due"] += ((now - item["due"]) // period + 1) * period
                offset = 24 if emu.get_ptr_size() == 8 else 16
                emu.mem_write(address + offset, item["due"].to_bytes(8, "little"))
            else:
                item["inserted"] = False
                emu.mem_write(address + 3, b"\0")

    def wait(self, api, emu, argv, ctx=None):
        address, reason, mode, alertable, timeout = map(int, argv)
        item = self.object(emu, address)
        if mode & 0xFF or alertable & 0xFF:
            raise ValueError("Alertable/user-mode kernel waits are not modeled")
        if emu.get_current_irql() > 2:
            raise ValueError("Kernel dispatcher wait above DISPATCH_LEVEL")
        emu.virtual_clock._observe()
        self.refresh(emu)
        if self.read_signal(emu, address) > 0:
            if item["kind"] in (1, 9):
                self.signal(emu, address, 0)
            return 0
        if timeout:
            require_range(emu, timeout, 8)
            value = int.from_bytes(emu.mem_read(timeout, 8), "little", signed=True)
            if not value:
                return 0x102
        else:
            value = None
        if emu.get_current_irql() > 1:
            raise ValueError("Blocking kernel dispatcher wait above APC_LEVEL")
        if emu.run_queue:
            raise ValueError("Blocked kernel dispatcher wait requires kernel thread scheduling")
        now = self.interrupt_time(emu)
        if value is None:
            if item["kind"] not in (8, 9) or not item["inserted"]:
                raise ValueError("Blocked kernel dispatcher wait requires kernel thread scheduling")
            deadline = item["due"]
        else:
            delta = -value if value < 0 else max(0, value - emu.virtual_clock.filetime_ticks())
            deadline = now + delta
            if item["kind"] in (8, 9) and item["inserted"]:
                deadline = min(deadline, item["due"])
        self.advance_to(emu, deadline)
        self.refresh(emu)
        if self.read_signal(emu, address) > 0:
            if item["kind"] in (1, 9):
                self.signal(emu, address, 0)
            return 0
        return 0x102

    def advance_to(self, emu, deadline):
        now = self.interrupt_time(emu)
        # Do not advance past a callback that would need to run first.
        callbacks = [item["due"] for item in self.objects.values()
                     if item["kind"] in (8, 9) and item["inserted"] and item["dpc"] and item["due"] <= deadline]
        if callbacks:
            deadline = min(deadline, min(callbacks))
        delta = max(0, deadline - now)
        if delta > 0xFFFFFFFF * 10000:
            raise ValueError("Kernel wait interval exceeds the modeled time range")
        emu.virtual_clock.advance_microseconds((delta + 9) // 10)
        self.refresh(emu)

    def delay(self, api, emu, argv, ctx=None):
        mode, alertable, interval = map(int, argv)
        if mode & 0xFF or alertable & 0xFF:
            raise ValueError("Alertable/user-mode kernel delay is not modeled")
        if emu.get_current_irql() > 1:
            raise ValueError("Kernel delay above APC_LEVEL")
        require_range(emu, interval, 8)
        value = int.from_bytes(emu.mem_read(interval, 8), "little", signed=True)
        if emu.run_queue:
            raise ValueError("Kernel delay with queued work requires kernel thread scheduling")
        clock = emu.virtual_clock
        clock._observe()
        delta = -value if value < 0 else max(0, value - clock.filetime_ticks())
        self.advance_to(emu, self.interrupt_time(emu) + delta)
        return 0

    def report(self):
        return {"objects": len(self.objects), "dpcs_initialized": len(self.dpcs),
                "timers": [{"address": hex(address), "inserted": item["inserted"],
                            "due_interrupt_time": item["due"], "period_ms": item["period"], "dpc": hex(item["dpc"])}
                           for address, item in sorted(self.objects.items()) if item["kind"] in (8, 9)],
                "scope": "Current-thread events, timer state and finite waits; queued threads and timer DPC execution require scheduling"}

    def install(self, handler):
        for name, function, argc in (("KeInitializeEvent", self.initialize_event, 3),
                ("KeInitializeTimer", self.initialize_timer, 1), ("KeInitializeTimerEx", self.initialize_timer, 2),
                ("KeInitializeDpc", self.initialize_dpc, 3),
                ("KeDelayExecutionThread", self.delay, 3),
                ("KeCancelTimer", self.cancel_timer, 1), ("KeWaitForSingleObject", self.wait, 5)):
            handler.funcs[name] = name, function, argc, arch.CALL_CONV_STDCALL, None
        for name, operation, argc in (("KeSetEvent", "set", 3), ("KeResetEvent", "reset", 1),
                ("KeClearEvent", "clear", 1), ("KeReadStateEvent", "read", 1)):
            def call(api, emu, argv, ctx=None, operation=operation):
                return self.event(operation, emu, argv)
            handler.funcs[name] = name, call, argc, arch.CALL_CONV_STDCALL, None
        for name, extended in (("KeSetTimer", False), ("KeSetTimerEx", True)):
            def call(api, emu, argv, ctx=None, extended=extended):
                return self.set_timer(extended, emu, argv)
            argc = (4 if extended else 3) + int(self.kernel.get_ptr_size() == 4)
            handler.funcs[name] = name, call, argc, arch.CALL_CONV_STDCALL, None
