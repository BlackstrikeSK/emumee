"""Cooperative execution of system threads requested by the guest driver."""

import time
from collections import deque
from .kernel_api import require_range, guest_range
from speakeasy import common
from speakeasy.winenv import arch


class KernelThreads:
    def __init__(self, kernel):
        self.kernel = kernel
        self.active = False
        self.contexts = {}
        self.ready = deque()
        self.pending = None
        self.transition = False
        self.root = None
        self.root_returned = False
        self.switches = deque(maxlen=256)
        self.switch_count = 0
        self.quantum_end = 256
        self.handles = {}
        self.closed_handles = set()
        self.original_close = None
        self.priorities = {}
        self.stack_count = 0
        from .kernel_ipi import KernelIpi
        self.ipi = KernelIpi(self)
        kernel.ipi = self.ipi

    def priority(self, api, emu, argv, ctx=None):
        address, priority = map(int, argv)
        priority &= 0xFFFFFFFF
        thread = emu.get_object_from_addr(address)
        if thread is None or not hasattr(thread, "tid") or not 1 <= priority <= 31:
            raise ValueError("Invalid thread or priority")
        self.priorities[address] = priority
        # This routine has no status result; dispatch remains cooperative.

    def attempt_objects(self, addresses, wait_all):
        emu = self.kernel
        items = [emu.dispatcher.object(emu, address) for address in addresses]
        signals = [emu.dispatcher.read_signal(emu, address) > 0 for address in addresses]
        if (not all(signals)) if wait_all else (not any(signals)):
            return None
        selected = list(range(len(addresses))) if wait_all else [signals.index(True)]
        for index in selected:
            if items[index]["kind"] in (1, 9):
                emu.dispatcher.signal(emu, addresses[index], 0)
        return 0 if wait_all else selected[0]

    def wait_many(self, api, emu, argv, ctx=None):
        count, array, wait_type, reason, mode, alertable, timeout, blocks = map(int, argv)
        count &= 0xFFFFFFFF
        wait_type &= 0xFFFFFFFF
        if not 1 <= count <= 64 or wait_type not in (0, 1) or mode & 0xFF or alertable & 0xFF:
            raise ValueError("Unsupported kernel multiple-object wait")
        width = emu.get_ptr_size()
        require_range(emu, array, count * width)
        if count > 3 and not blocks:
            raise ValueError("Large kernel wait requires caller wait-block storage")
        if blocks:
            require_range(emu, blocks, count * (48 if width == 8 else 24), True)
        raw = emu.mem_read(array, count * width)
        addresses = [int.from_bytes(raw[index * width:(index + 1) * width], "little") for index in range(count)]
        if len(set(addresses)) != count:
            raise ValueError("Duplicate dispatcher objects in a kernel wait")
        emu.virtual_clock._observe()
        emu.dispatcher.refresh(emu)
        status = self.attempt_objects(addresses, wait_type == 0)
        if status is not None:
            return status
        deadline = None
        if timeout:
            require_range(emu, timeout, 8)
            value = int.from_bytes(emu.mem_read(timeout, 8), "little", signed=True)
            if not value:
                return 0x102
            delta = -value if value < 0 else max(0, value - emu.virtual_clock.filetime_ticks())
            deadline = emu.dispatcher.interrupt_time(emu) + delta
        if emu.get_current_irql() > 1:
            raise ValueError("Blocking kernel multiple-object wait above APC_LEVEL")
        if self.root is None:
            if deadline is None:
                raise ValueError("Blocked multiple-object wait requires kernel thread scheduling")
            for _ in range(4096):
                due = [item["due"] for address, item in emu.dispatcher.objects.items()
                       if address in addresses and item["kind"] in (8, 9) and item["inserted"]]
                emu.dispatcher.advance_to(emu, min([deadline] + due))
                status = self.attempt_objects(addresses, wait_type == 0)
                if status is not None:
                    return status
                if emu.dispatcher.interrupt_time(emu) >= deadline:
                    return 0x102
            raise ValueError("Multiple-object timer transition limit reached")
        self.pending = {"kind": "wait_many", "objects": addresses, "wait_all": wait_type == 0, "deadline": deadline}
        return None

    def count(self):
        return sum(run.instr_cnt for run in self.kernel.runs)

    def capture(self, run, state):
        emu = self.kernel
        emu.cpu_model.flush_cycles()
        row = self.contexts.setdefault(id(run), {"run": run, "started": True})
        row.update(state=state, cpu=emu.emu_eng.emu.context_save(), stack=emu.stack_base,
                   irql=emu.get_current_irql(), critical=emu.synchronization.critical_depth,
                   processor=getattr(emu, "processor_id", 0),
                   thread_stack=(run.thread.stack_base, run.thread.stack_commit))
        return row

    def create(self, api, emu, argv, ctx=None):
        output, access, attributes, process, client_id, start, argument = map(int, argv)
        width = emu.get_ptr_size()
        require_range(emu, output, width, True)
        if client_id:
            require_range(emu, client_id, width * 2, True)
        if emu.get_current_irql() or process:
            raise ValueError("Candidate supports System-process threads at PASSIVE_LEVEL")
        if attributes:
            size = 48 if width == 8 else 24
            require_range(emu, attributes, size)
            blob = emu.mem_read(attributes, size)
            offset = 8 if width == 8 else 4
            root = int.from_bytes(blob[offset:offset + width], "little")
            name = int.from_bytes(blob[offset + width:offset + width * 2], "little")
            flags = int.from_bytes(blob[offset + width * 2:offset + width * 2 + 4], "little")
            security = int.from_bytes(blob[-width * 2:], "little")
            if int.from_bytes(blob[:4], "little") != size or root or name or security or flags & ~0x240:
                raise ValueError("Unsupported system thread object attributes")
        if not guest_range(emu, start, 1, 4):
            raise ValueError("System thread start is not executable")
        if sum(row["run"].type == "system_thread" for row in self.contexts.values()) >= 64:
            return 0xC000009A
        owner = emu.get_system_process()
        handle, thread = emu.create_thread(start, argument, owner, thread_type="system_thread")
        if not thread:
            return 0xC000009A
        self.active = True
        if self.root is None:
            self.root = emu.curr_run
        thread.ref_cnt += 1  # The running thread survives closure of its handle.
        self.handles[handle] = thread
        header_size = 24 if width == 8 else 16
        emu.dispatcher.header(emu, thread.address, 6, header_size)
        emu.dispatcher.objects[thread.address] = {"kind": 6, "size": header_size}
        thread.read_back()
        if thread not in owner.threads:
            owner.threads.append(thread)
        emu.mem_write(output, handle.to_bytes(width, "little"))
        if client_id:
            emu.mem_write(client_id, owner.pid.to_bytes(width, "little") + thread.tid.to_bytes(width, "little"))
        return 0

    def close(self, api, emu, argv, ctx=None):
        handle = int(argv[0])
        if handle in self.closed_handles:
            return 0xC0000008
        thread = self.handles.pop(handle, None)
        if thread is None:
            return self.original_close[1](api, emu, argv, ctx)
        thread.handles.remove(handle)
        emu.om.dec_ref(thread)
        self.closed_handles.add(handle)
        return 0

    def wait(self, api, emu, argv, ctx=None):
        if self.root is None:
            return emu.dispatcher.wait(api, emu, argv, ctx)
        address, reason, mode, alertable, timeout = map(int, argv)
        item = emu.dispatcher.object(emu, address)
        if mode & 0xFF or alertable & 0xFF or emu.get_current_irql() > 1:
            raise ValueError("Candidate supports nonalertable PASSIVE/APC kernel event waits")
        emu.virtual_clock._observe()
        emu.dispatcher.refresh(emu)
        if emu.dispatcher.read_signal(emu, address) > 0:
            if item["kind"] in (1, 9):
                emu.dispatcher.signal(emu, address, 0)
            return 0
        if timeout:
            require_range(emu, timeout, 8)
            value = int.from_bytes(emu.mem_read(timeout, 8), "little", signed=True)
            if value == 0:
                return 0x102
            delta = -value if value < 0 else max(0, value - emu.virtual_clock.filetime_ticks())
            deadline = emu.dispatcher.interrupt_time(emu) + delta
        else:
            deadline = None
        if self.root is None:
            raise ValueError("Blocked kernel event has no guest-created threads")
        self.pending = {"kind": "wait", "object": address, "deadline": deadline}
        return None

    def delay(self, api, emu, argv, ctx=None):
        if self.root is None:
            return emu.dispatcher.delay(api, emu, argv, ctx)
        mode, alertable, pointer = map(int, argv)
        if mode & 0xFF or alertable & 0xFF or emu.get_current_irql() > 1:
            raise ValueError("Unsupported kernel thread delay mode/IRQL")
        require_range(emu, pointer, 8)
        emu.virtual_clock._observe()
        value = int.from_bytes(emu.mem_read(pointer, 8), "little", signed=True)
        delta = -value if value < 0 else max(0, value - emu.virtual_clock.filetime_ticks())
        self.pending = {"kind": "delay", "deadline": emu.dispatcher.interrupt_time(emu) + delta}

    def terminate(self, api, emu, argv, ctx=None):
        if self.root is None or emu.curr_run.type != "system_thread" or emu.get_current_irql():
            raise ValueError("PsTerminateSystemThread outside a spawned system thread at PASSIVE_LEVEL")
        self.pending = {"kind": "exit", "status": int(argv[0]) & 0xFFFFFFFF}

    def finish_thread(self, thread):
        emu = self.kernel
        emu.dispatcher.signal(emu, thread.address, 1)
        emu.om.dec_ref(thread)
        if thread.ref_cnt <= 0:
            emu.dispatcher.objects.pop(thread.address, None)

    def yield_at_hook(self):
        if self.root is not None and self.pending is None:
            self.ingest()
            ipi_slice = self.ipi.active is not None and self.kernel.curr_run.type == "kernel_ipi" and bool(self.ipi.ready)
            if self.count() >= self.quantum_end and (ipi_slice or
                    (self.ipi.active is None and self.ready and self.kernel.get_current_irql() < 2)):
                self.pending = {"kind": "quantum"}
        if self.pending is None:
            return False
        emu = self.kernel
        kind = self.pending["kind"]
        row = self.capture(emu.curr_run, "ready" if kind == "quantum" else "done" if kind == "exit" else "waiting")
        row["pending"] = self.pending
        if kind in ("wait", "wait_many", "delay", "ipi"):
            event = emu.curr_run.events[-1]
            expected = {"wait": "ntoskrnl.KeWaitForSingleObject", "wait_many": "ntoskrnl.KeWaitForMultipleObjects",
                        "delay": "ntoskrnl.KeDelayExecutionThread", "ipi": "ntoskrnl.KeIpiGenericCall"}[kind]
            if getattr(event, "api_name", None) != expected:
                raise ValueError("Deferred wait has no matching API observation")
            event.ret_val = None
            row["event"] = event
        elif kind == "quantum":
            (self.ipi.ready if emu.curr_run.type == "kernel_ipi" else self.ready).append(id(emu.curr_run))
        elif kind == "exit":
            self.finish_thread(emu.curr_run.thread)
        self.pending = None
        self.transition = True
        emu.emu_eng.stop()
        return True

    def complete(self):
        emu = self.kernel
        if self.yield_at_hook():
            return None
        if self.root is None:
            return emu._complete_lifecycle_run()
        if emu.curr_run.error:
            emu.on_emu_complete()
            return None
        if emu.get_pc() not in (emu.return_hook, emu.exit_hook):
            raise ValueError("Kernel thread completion without a return or termination")
        row = self.capture(emu.curr_run, "returned" if emu.curr_run is self.root else "done")
        emu.curr_run.ret_val = emu.get_return_val()
        emu.returned_runs.add(id(emu.curr_run))
        if emu.curr_run is self.root:
            self.root_returned = True
        elif emu.curr_run.type == "kernel_ipi":
            self.ipi.finish_member(row)
        else:
            self.finish_thread(emu.curr_run.thread)
        self.transition = True
        emu.emu_eng.stop()
        return None

    def ingest(self):
        emu = self.kernel
        while emu.run_queue:
            run = emu.run_queue.pop(0)
            if run.type != "system_thread":
                raise ValueError("Candidate cannot schedule a synthetic kernel callback")
            key = id(run)
            if key not in self.contexts:
                self.contexts[key] = {"run": run, "started": False, "state": "ready"}
                self.ready.append(key)

    def wake(self):
        emu = self.kernel
        emu.dispatcher.refresh(emu)
        now = emu.dispatcher.interrupt_time(emu)
        for key, row in self.contexts.items():
            if row["state"] != "waiting":
                continue
            pending = row["pending"]
            if pending["kind"] == "ipi":
                continue
            if pending["kind"] in ("wait", "wait_many"):
                addresses = pending["objects"] if pending["kind"] == "wait_many" else [pending["object"]]
                status = self.attempt_objects(addresses, pending.get("wait_all", True))
                if status is None and (pending["deadline"] is None or pending["deadline"] > now):
                    continue
                if status is None:
                    status = 0x102
            else:
                if pending["deadline"] > now:
                    continue
                status = 0
            row["state"] = "ready"
            row["result"] = status
            row["event"].ret_val = hex(status)
            self.ready.append(key)

    def resume(self, row):
        emu = self.kernel
        run = row["run"]
        if not row["started"]:
            size = 0x10000
            if "stack_map" in row:
                address = row["stack_map"]
                emu.mem_write(address, bytes(size))
            else:
                self.stack_count += 1
                base = (0xFFFFA00000000000 if emu.get_ptr_size() == 8 else 0xB0000000) + self.stack_count * 0x100000
                address = emu.mem_map(size, base=base, perms=common.PERM_MEM_RW, tag="emu.kernel.thread_stack")
            emu.stack_base = address + size
            emu.reset_stack(emu.stack_base)
            emu.reset_cpu_context()
            emu._prepare_run_context(run)
            critical = row.get("initial_critical", 1)  # PsCreateSystemThread contract.
            irql = row.get("initial_irql", 0)
            row.update(started=True, state="running", stack=emu.stack_base)
            run.thread.stack_base = emu.stack_base
            run.thread.stack_commit = address
        else:
            emu.emu_eng.emu.context_restore(row["cpu"])
            emu.stack_base = row["stack"]
            emu.curr_run = run
            emu.curr_mod = emu.get_module_from_addr(run.start_addr)
            emu.set_current_process(run.process_context or emu.get_system_process())
            emu.set_current_thread(run.thread)
            critical, irql = row["critical"], row["irql"]
            run.thread.stack_base, run.thread.stack_commit = row["thread_stack"]
            if "result" in row:
                emu.reg_write(arch.AMD64_REG_RAX if emu.get_ptr_size() == 8 else arch.X86_REG_EAX,
                              row.pop("result"))
            row["state"] = "running"
        self.ipi.activate(row.get("processor", 0))
        emu.synchronization.critical_depth = critical
        emu.set_current_irql(irql)
        width = emu.get_ptr_size()
        current = emu.gs_addr + 0x188 if width == 8 else emu.fs_addr + 0x124
        emu.mem_write(current, run.thread.address.to_bytes(width, "little"))
        emu.previous_instruction = None
        self.quantum_end = self.count() + 256
        emu.run_complete = False
        self.switches.append({"tid": run.thread.tid, "pc": hex(emu.get_pc()),
                              "processor": getattr(emu, "processor_id", 0), "run_type": run.type})
        self.switch_count += 1

    def advance(self):
        if self.kernel.deadline is not None and time.monotonic() >= self.kernel.deadline:
            self.kernel.timeout_reached = True
            self.kernel.on_emu_complete()
            return False
        self.transition = False
        self.ingest()
        if self.ipi.advance():
            return True
        self.wake()
        if self.ready:
            self.resume(self.contexts[self.ready.popleft()])
            return True
        if self.root_returned:
            row = self.contexts[id(self.root)]
            self.resume(row)
            row["state"] = "returned"
            following = self.kernel._complete_lifecycle_run()
            if following is not None and not self.kernel.emu_complete:
                self.root = following
                self.root_returned = False
            return not self.kernel.emu_complete
        for _ in range(4096):
            if self.kernel.deadline is not None and time.monotonic() >= self.kernel.deadline:
                self.kernel.timeout_reached = True
                self.kernel.on_emu_complete()
                return False
            deadlines = [row["pending"]["deadline"] for row in self.contexts.values()
                         if row["state"] == "waiting" and row["pending"]["deadline"] is not None]
            deadlines.extend(item["due"] for item in self.kernel.dispatcher.objects.values()
                             if item["kind"] in (8, 9) and item["inserted"])
            if not deadlines:
                break
            self.kernel.dispatcher.advance_to(self.kernel, min(deadlines))
            self.wake()
            if self.ready:
                self.resume(self.contexts[self.ready.popleft()])
                return True
        raise ValueError("No runnable kernel thread can satisfy the blocked wait")

    def install(self):
        handler = self.kernel.api.load_api_handler("ntoskrnl")
        self.ipi.install(handler)
        for name, function, argc in (("PsCreateSystemThread", self.create, 7),
                ("PsTerminateSystemThread", self.terminate, 1), ("KeWaitForSingleObject", self.wait, 5),
                ("KeDelayExecutionThread", self.delay, 3), ("KeWaitForMultipleObjects", self.wait_many, 8),
                ("KeSetActualBasePriorityThread", self.priority, 2)):
            handler.funcs[name] = name, function, argc, arch.CALL_CONV_STDCALL, None
        def thread_id(api, emu, argv, ctx=None):
            return emu.get_current_thread().tid
        handler.funcs["PsGetCurrentThreadId"] = "PsGetCurrentThreadId", thread_id, 0, arch.CALL_CONV_STDCALL, None
        self.original_close = handler.funcs["ZwClose"]
        handler.funcs["ZwClose"] = "ZwClose", self.close, 1, arch.CALL_CONV_STDCALL, None

    def execute_after_yield(self, result):
        kernel = self.kernel
        while self.transition and not kernel.emu_complete:
            try:
                if not self.advance():
                    break
                kernel.emu_eng.start(kernel.get_pc(), timeout=kernel.config.timeout, count=(1 << 63) - 1)
            except Exception as error:
                if kernel.curr_run.error is None:
                    kernel.curr_run.error = kernel.get_error_info("kernel_thread_execution", kernel.get_pc()).model_copy(
                        update={"context_summary": str(error)[:512]})
                kernel.lifecycle_errors.append("Kernel thread scheduling: " + str(error))
                kernel.on_emu_complete()
        return result

    def report(self):
        threads = []
        for row in self.contexts.values():
            run = row["run"]
            if run.type != "system_thread":
                continue
            pending = row.get("pending") or {}
            threads.append({"tid": run.thread.tid, "pid": run.thread.process.pid,
                "object": hex(run.thread.address), "start": hex(run.start_addr),
                "state": row["state"], "started": row["started"], "instruction_count": run.instr_cnt,
                "wait_kind": pending.get("kind"), "exit_status": pending.get("status"),
                "recorded_priority": self.priorities.get(run.thread.address, 8)})
        return {"threads": threads, "switches_observed": self.switch_count,
                "switch_tail": list(self.switches), "open_thread_handles": len(self.handles),
                "scope": "Cooperative CPU-0 guest-created System threads and requested logical-processor IPI callbacks; priorities are recorded; no general DPC/APC or hardware dispatch"}
