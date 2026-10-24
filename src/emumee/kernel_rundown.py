"""Opaque cache-aware rundown references on the modeled current CPU."""

from speakeasy.winenv import arch
from .kernel_api import require_range


class CacheAwareRundown:
    """Opaque references for the currently modeled CPU; no blocked wait success."""

    def __init__(self, kernel):
        self.kernel = kernel
        self.records = {}

    def allocate(self, _api, emu, argv, ctx=None):
        if emu.get_current_irql() > 1:
            raise ValueError("Cache-aware rundown allocation above APC_LEVEL")
        if len(self.records) >= 1024:
            return 0
        pool, tag = map(int, argv)
        # This is opaque provider-owned storage, not a Windows internal layout.
        count = emu.kernel_environment.logical
        size = 64 * (count + 1)
        text = (tag & 0xFFFFFFFF).to_bytes(4, "little").decode("ascii", errors="replace")
        pointer = emu.pool_alloc(pool, size, text)
        if pointer:
            self.records[pointer] = {"references": 0, "running_down": False, "size": size}
        return pointer

    def operation(self, operation, emu, argv):
        pointer = int(argv[0])
        record = self.records.get(pointer)
        if record is None:
            raise ValueError("Invalid cache-aware rundown reference")
        require_range(emu, pointer, record["size"])
        count = (int(argv[1]) & 0xFFFFFFFF) if len(argv) > 1 else 1
        if emu.get_current_irql() > 2:
            raise ValueError("Cache-aware rundown access above DISPATCH_LEVEL")
        if operation == "acquire":
            if record["running_down"]:
                return 0
            maximum = (1 << (emu.get_ptr_size() * 8 - 1)) - 1
            if record["references"] + count > maximum:
                raise ValueError("Cache-aware rundown reference count overflow")
            record["references"] += count
            return 1
        if operation == "release":
            if count > record["references"]:
                raise ValueError("Cache-aware rundown release exceeds acquired references")
            record["references"] -= count
        elif operation in ("wait", "free"):
            if emu.get_current_irql() > 1:
                raise ValueError("Cache-aware rundown teardown above APC_LEVEL")
            if operation == "wait":
                record["running_down"] = True
            if record["references"]:
                raise ValueError("Blocked cache-aware rundown teardown requires kernel thread scheduling")
            if operation == "free":
                emu.mem_free(pointer)
                del self.records[pointer]

    def install(self, handler):
        handler.funcs["ExAllocateCacheAwareRundownProtection"] = (
            "ExAllocateCacheAwareRundownProtection", self.allocate, 2, arch.CALL_CONV_STDCALL, None)
        for name, operation, argc, fastcall in (
            ("ExFreeCacheAwareRundownProtection", "free", 1, False),
            ("ExAcquireRundownProtectionCacheAwareEx", "acquire", 2, True),
            ("ExReleaseRundownProtectionCacheAwareEx", "release", 2, True),
            ("ExAcquireRundownProtectionCacheAware", "acquire", 1, True),
            ("ExReleaseRundownProtectionCacheAware", "release", 1, True),
            ("ExWaitForRundownProtectionReleaseCacheAware", "wait", 1, True),
        ):
            def call(api, emu, argv, ctx=None, operation=operation):
                return self.operation(operation, emu, argv)
            handler.funcs[name] = name, call, argc, (arch.CALL_CONV_FASTCALL if fastcall else arch.CALL_CONV_STDCALL), None

    def report(self):
        return {"references": [{"address": hex(address), "references": item["references"],
                                "running_down": item["running_down"]}
                               for address, item in sorted(self.records.items())],
                "scope": "Opaque references on the current CPU; blocking teardown requires a scheduler"}
