"""Uncontended Windows 8+ kernel synchronization on the modeled current thread.

Guarded mutexes use the installed WDK's FAST_MUTEX layout. Blocking waits need
a kernel scheduler and stop visibly instead of granting an unavailable lock.
"""

import struct

from .kernel_api import require_range


class KernelSynchronization:
    def __init__(self, kernel):
        self.kernel = kernel
        self.held_mutexes = set()
        self.critical_depth = 0

    def read(self, address, size=None):
        size = size or self.kernel.get_ptr_size()
        require_range(self.kernel, address, size)
        return int.from_bytes(self.kernel.mem_read(address, size), "little")

    def write(self, address, value, size=None):
        size = size or self.kernel.get_ptr_size()
        require_range(self.kernel, address, size, True)
        self.kernel.mem_write(address, value.to_bytes(size, "little"))

    def mutex_layout(self, address):
        width = self.kernel.get_ptr_size()
        event, old_irql, size = (24, 48, 56) if width == 8 else (12, 28, 32)
        require_range(self.kernel, address, size)
        require_range(self.kernel, address, size, True)
        return width, event, old_irql, size

    def initialize_mutex(self, _api, emu, argv, ctx=None):
        address = int(argv[0])
        width, event, _old_irql, size = self.mutex_layout(address)
        if address in self.held_mutexes:
            raise ValueError("Reinitializing an owned guarded mutex")
        data = bytearray(size)
        struct.pack_into("<i", data, 0, 1)
        data[event] = 1  # SynchronizationEvent
        data[event + 2] = (24 if width == 8 else 16) // 4
        head = address + event + 8
        data[event + 8:event + 8 + width * 2] = head.to_bytes(width, "little") * 2
        emu.mem_write(address, bytes(data))

    def acquire_mutex(self, _api, emu, argv, ctx=None):
        address = int(argv[0])
        width, _event, old_irql, _size = self.mutex_layout(address)
        if emu.get_current_irql() > 1:
            raise ValueError("Guarded mutex acquisition above APC_LEVEL")
        if self.read(address, 4) != 1:
            raise ValueError("Blocked guarded mutex acquisition requires kernel thread scheduling")
        if len(self.held_mutexes) >= 4096:
            raise ValueError("Modeled guarded mutex ownership limit exceeded")
        self.write(address, 0, 4)
        self.write(address + width, emu.get_current_thread().address)
        self.write(address + old_irql, emu.get_current_irql(), 4)
        self.held_mutexes.add(address)
        emu.set_current_irql(1)

    def release_mutex(self, _api, emu, argv, ctx=None):
        address = int(argv[0])
        width, _event, old_irql, _size = self.mutex_layout(address)
        if self.read(address, 4) != 0 or self.read(address + width) != emu.get_current_thread().address:
            raise ValueError("Guarded mutex release by a thread that does not own it")
        previous = self.read(address + old_irql, 4)
        if previous > 1 or emu.get_current_irql() != 1:
            raise ValueError("Guarded mutex release has an invalid saved/current IRQL")
        self.write(address + width, 0)
        self.write(address, 1, 4)
        self.held_mutexes.discard(address)
        emu.set_current_irql(previous)

    def rundown(self, operation, emu, argv):
        address = int(argv[0])
        value = self.read(address)
        width = emu.get_ptr_size()
        require_range(emu, address, width, True)
        if operation == "initialize":
            self.write(address, 0)
        elif operation == "acquire":
            if value & 1:
                return 0
            if value > (1 << (width * 8)) - 3:
                raise ValueError("Rundown reference count overflow")
            self.write(address, value + 2)
            return 1
        elif operation == "release":
            if value < 2:
                raise ValueError("Rundown release without a reference")
            self.write(address, value - 2)
        elif operation == "wait":
            self.write(address, value | 1)
            if value not in (0, 1):
                raise ValueError("Blocked rundown wait requires kernel thread scheduling")

    def push_lock(self, operation, emu, argv):
        address = int(argv[0])
        value = self.read(address)
        require_range(emu, address, emu.get_ptr_size(), True)
        if len(argv) > 1 and int(argv[1]) & 0xFFFFFFFF:
            raise ValueError("Unsupported push-lock flags")
        if operation == "initialize":
            self.write(address, 0)
        elif operation == "acquire":
            if value:
                raise ValueError("Blocked push-lock acquisition requires kernel thread scheduling")
            self.write(address, 1)
        elif operation == "release":
            if value != 1:
                raise ValueError("Exclusive push-lock release without exclusive ownership")
            self.write(address, 0)

    def critical(self, enter):
        if enter:
            self.critical_depth += 1
        elif not self.critical_depth:
            raise ValueError("Leaving a kernel critical region that was not entered")
        else:
            self.critical_depth -= 1

    def raise_irql(self, _api, emu, argv, ctx=None):
        previous = emu.get_current_irql()
        new = int(argv[0]) & 0xFF
        if new < previous:
            raise ValueError("KfRaiseIrql cannot lower the current IRQL")
        emu.set_current_irql(new)
        return previous

    def lower_irql(self, _api, emu, argv, ctx=None):
        new = int(argv[0]) & 0xFF
        if new > emu.get_current_irql():
            raise ValueError("KeLowerIrql cannot raise the current IRQL")
        emu.set_current_irql(new)

    def report(self):
        return {"irql": self.kernel.get_current_irql(), "critical_region_depth": self.critical_depth,
                "held_guarded_mutexes": [hex(address) for address in sorted(self.held_mutexes)],
                "scope": "Uncontended current-thread synchronization; blocking kernel scheduling is unsupported"}

    def install(self, handler):
        from speakeasy.winenv import arch
        def bind(name, function, count, fastcall=False):
            handler.funcs[name] = name, function, count, (arch.CALL_CONV_FASTCALL if fastcall else arch.CALL_CONV_STDCALL), None
        for name, function in (("KeInitializeGuardedMutex", self.initialize_mutex),
                ("KeAcquireGuardedMutex", self.acquire_mutex), ("KeReleaseGuardedMutex", self.release_mutex),
                ("KfRaiseIrql", self.raise_irql), ("KeLowerIrql", self.lower_irql), ("KfLowerIrql", self.lower_irql)):
            bind(name, function, 1, name in ("KfRaiseIrql", "KeLowerIrql", "KfLowerIrql"))
        for prefix, operation in (("ExInitialize", "initialize"), ("ExAcquire", "acquire"),
                ("ExRelease", "release"), ("ExWaitFor", "wait")):
            suffix = "RundownProtectionRelease" if operation == "wait" else "RundownProtection"
            def rundown(api, emu, argv, ctx=None, operation=operation):
                return self.rundown(operation, emu, argv)
            bind(prefix + suffix, rundown, 1, True)
        for name, operation, count in (("ExInitializePushLock", "initialize", 1),
                ("ExAcquirePushLockExclusiveEx", "acquire", 2), ("ExReleasePushLockExclusiveEx", "release", 2)):
            def push(api, emu, argv, ctx=None, operation=operation):
                return self.push_lock(operation, emu, argv)
            bind(name, push, count, operation != "initialize")
        bind("KeGetCurrentIrql", lambda api, emu, argv, ctx=None: emu.get_current_irql(), 0)
        bind("KeAreAllApcsDisabled", lambda api, emu, argv, ctx=None: int(emu.get_current_irql() >= 1), 0)
        bind("KeAreApcsDisabled", lambda api, emu, argv, ctx=None: int(bool(self.critical_depth) or emu.get_current_irql() >= 1), 0)
        bind("KeEnterCriticalRegion", lambda api, emu, argv, ctx=None: self.critical(True), 0)
        bind("KeLeaveCriticalRegion", lambda api, emu, argv, ctx=None: self.critical(False), 0)
        bind("ExGetPreviousMode", lambda api, emu, argv, ctx=None: 0, 0)
