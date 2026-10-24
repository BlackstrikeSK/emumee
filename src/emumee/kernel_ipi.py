"""Bounded cooperative logical-processor broadcasts requested by the guest."""

from collections import deque
import struct

from speakeasy import common
from speakeasy.profiler import Run
from speakeasy.windows import objman
from speakeasy.winenv import arch
from unicorn import x86_const as ux

from .kernel_api import guest_range


class KernelIpi:
    def __init__(self, scheduler):
        self.scheduler = scheduler
        self.kernel = scheduler.kernel
        self.active = None
        self.ready = deque()
        self.processors = {}
        self.stacks = {}
        self.interrupted_threads = {}
        self.broadcasts = []

    def install(self, handler):
        handler.funcs["KeIpiGenericCall"] = ("KeIpiGenericCall", self.call, 2, arch.CALL_CONV_STDCALL, None)

    def call(self, api, emu, argv, ctx=None):
        routine, argument = map(int, argv)
        level = 14 if emu.get_ptr_size() == 8 else 29
        if self.active is not None or emu.get_current_irql() >= level:
            raise ValueError("Kernel IPI broadcast requires IRQL below IPI_LEVEL and no nested broadcast")
        logical = emu.kernel_environment.logical
        maximum = emu.get_ptr_size() * 8
        if not 1 <= logical <= maximum:
            raise ValueError(f"Kernel IPI broadcast supports one processor group of up to {maximum} processors")
        if len(self.broadcasts) >= 64:
            raise ValueError("Kernel IPI broadcast limit exceeded")
        if not guest_range(emu, routine, 1, 4):
            raise ValueError("Kernel IPI callback is not executable guest code")
        manager = self.scheduler
        manager.active = True
        if manager.root is None:
            manager.root = emu.curr_run
        manager.pending = {"kind": "ipi", "routine": routine, "argument": argument}

    def ensure_processor(self, number):
        emu = self.kernel
        if number in self.processors:
            return self.processors[number]
        width = emu.get_ptr_size()
        if 0 not in self.processors:
            self.processors[0] = emu.gs_addr if width == 8 else emu.fs_addr
        if number == 0:
            return self.processors[0]
        base = (0xFFFFF80000000000 if width == 8 else 0xFF800000) + number * 0x10000
        address = emu.mem_map(4096, base=base, perms=common.PERM_MEM_RW, tag=f"emu.kernel.pcr.cpu{number}")
        emu.mem_write(address, emu.mem_read(self.processors[0], 4096))
        if width == 8:
            prcb = address + 0x180
            for offset, value in ((0x18, address), (0x20, prcb), (0x28, prcb + 0x6F0)):
                emu.mem_write(address + offset, value.to_bytes(8, "little"))
            # WDK ksamd64.inc: PcNumber=0x1A4, PbNumber=0x24.
            emu.mem_write(address + 0x1A4, number.to_bytes(4, "little"))
            emu.mem_write(address + 0x184, bytes([number]))  # LegacyNumber.
        else:
            for offset, value in ((0x1C, address), (0x20, address + 0x120)):
                emu.mem_write(address + offset, value.to_bytes(4, "little"))
            emu.mem_write(address + 0x51, bytes([number]))
            # WDK ntddk.h KPCR: SetMemberCopy=0x14, SetMember=0x48.
            for offset in (0x14, 0x48):
                emu.mem_write(address + offset, (1 << number).to_bytes(4, "little"))
        self.processors[number] = address
        return address

    def activate(self, number):
        emu = self.kernel
        address = self.ensure_processor(number)
        engine = emu.emu_eng.emu
        if emu.get_ptr_size() == 8:
            emu.gs_addr = address
            engine.reg_write(ux.UC_X86_REG_GS_BASE, address)
        else:
            emu.fs_addr = address
            selector = int(engine.reg_read(ux.UC_X86_REG_FS))
            if not selector & ~7:
                raise ValueError("Kernel IPI context requires an initialized FS selector")
            descriptor = engine.reg_read(ux.UC_X86_REG_GDTR)[1] + (selector & ~7)
            raw = bytearray(emu.mem_read(descriptor, 8))
            struct.pack_into("<H", raw, 2, address & 0xFFFF)
            raw[4], raw[7] = (address >> 16) & 255, (address >> 24) & 255
            emu.mem_write(descriptor, bytes(raw))
            engine.reg_write(ux.UC_X86_REG_FS, selector)
        emu.processor_id = number
        engine.msr_write(0xC0000103, number)  # IA32_TSC_AUX agrees with RDTSCP.
        if emu.cpu_model is not None:
            emu.cpu_model.processor_id = number

    def begin(self, parent):
        emu = self.kernel
        request = parent["pending"]
        count = emu.kernel_environment.logical
        source = parent.get("processor", 0)
        group = {"routine": hex(request["routine"]), "argument": hex(request["argument"]),
                 "source_processor": source, "processors": count, "completed": False,
                 "results": {}, "members": []}
        self.broadcasts.append(group)
        self.active = {"parent": parent, "group": group, "members": set()}
        level = 14 if emu.get_ptr_size() == 8 else 29
        owner = emu.get_system_process()
        for number in range(count):
            pcr = self.ensure_processor(number)
            emu.mem_write(pcr + (0x50 if emu.get_ptr_size() == 8 else 0x24), bytes([level]))
            if number == source:
                thread = parent["run"].thread
            else:
                thread = self.interrupted_threads.get(number)
                if thread is None:
                    # These parked System contexts describe the modeled CPU's
                    # interrupted environment; no guest thread routine runs.
                    thread = objman.Thread(emu)
                    thread.process = owner
                    owner.threads.append(thread)
                    emu.add_object(thread)
                    self.interrupted_threads[number] = thread
            run = Run()
            run.type, run.start_addr, run.args = "kernel_ipi", request["routine"], [request["argument"]]
            current = pcr + (0x188 if emu.get_ptr_size() == 8 else 0x124)
            emu.mem_write(current, thread.address.to_bytes(emu.get_ptr_size(), "little"))
            run.thread = thread
            run.process_context = (parent["run"].process_context or owner) if number == source else owner
            if number not in self.stacks:
                base = (0xFFFFB00000000000 if emu.get_ptr_size() == 8 else 0xC0000000) + number * 0x100000
                self.stacks[number] = emu.mem_map(0x10000, base=base, perms=common.PERM_MEM_RW,
                                                tag=f"emu.kernel.ipi_stack.cpu{number}")
            row = {"run": run, "started": False, "state": "ready", "processor": number,
                   "initial_irql": level, "initial_critical": parent["critical"] if number == source else 0,
                   "stack_map": self.stacks[number]}
            key = id(run)
            self.scheduler.contexts[key] = row
            self.ready.append(key)
            self.active["members"].add(key)
            group["members"].append({"processor": number, "run_key": key})

    def finish_member(self, row):
        frame = self.active
        if frame is None or id(row["run"]) not in frame["members"]:
            raise ValueError("IPI callback returned outside its broadcast")
        expected = 14 if self.kernel.get_ptr_size() == 8 else 29
        if row["irql"] != expected:
            self.kernel.lifecycle_errors.append(f"IPI callback returned at IRQL {row['irql']}; expected IPI_LEVEL {expected}")
            self.kernel.on_emu_complete()
            return
        frame["group"]["results"][str(row["processor"])] = hex(row["run"].ret_val)

    def advance(self):
        frame = self.active
        if frame is None:
            parent = next((row for row in self.scheduler.contexts.values()
                           if row["state"] == "waiting" and row.get("pending", {}).get("kind") == "ipi"), None)
            if parent is None:
                return False
            self.begin(parent)
            frame = self.active
        if self.ready:
            self.scheduler.resume(self.scheduler.contexts[self.ready.popleft()])
            return True
        if any(self.scheduler.contexts[key]["state"] != "done" for key in frame["members"]):
            raise ValueError("IPI broadcast has an incomplete callback without a runnable processor")
        parent, group = frame["parent"], frame["group"]
        result = int(group["results"][str(group["source_processor"])], 0)
        parent.update(state="ready", result=result)
        parent["event"].ret_val = hex(result)
        self.scheduler.ready.appendleft(id(parent["run"]))
        group["completed"] = True
        for number, pcr in self.processors.items():
            self.kernel.mem_write(pcr + (0x50 if self.kernel.get_ptr_size() == 8 else 0x24),
                                  bytes([parent["irql"] if number == group["source_processor"] else 0]))
        self.active = None
        return False

    def report(self):
        groups = []
        for group in self.broadcasts:
            value = {key: item for key, item in group.items() if key != "members"}
            value["callbacks"] = [{"processor": member["processor"],
                "started": self.scheduler.contexts[member["run_key"]]["started"],
                "state": self.scheduler.contexts[member["run_key"]]["state"],
                "instruction_count": self.scheduler.contexts[member["run_key"]]["run"].instr_cnt}
                for member in group["members"]]
            groups.append(value)
        return {"broadcasts": groups, "current_processor": getattr(self.kernel, "processor_id", 0),
                "scope": "Cooperative one-group IPI rendezvous; separate CPU/PCR/stack contexts; parked System contexts on remote CPUs; no general interrupt or hardware emulation"}
