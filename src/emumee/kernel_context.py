"""Guest kernel segment and processor context from the WDK KPCR layouts."""

import struct
from unicorn import x86_const as ux
from .kernel_cpu import KernelCpu


def initialize_kernel_context(kernel):
    engine = kernel.emu_eng.emu
    width = kernel.get_ptr_size()
    gdt = engine.reg_read(ux.UC_X86_REG_GDTR)[1]
    idt = engine.reg_read(ux.UC_X86_REG_IDTR)[1]
    # Windows' documented WDK selector values (ksamd64.inc). Preserve the
    # engine's user/FS/GS descriptors, which occupy different slots.
    code = 0x00AF9A000000FFFF if width == 8 else 0x00CF9A000000FFFF
    data = 0x00CF92000000FFFF
    code_selector, data_selector = (0x10, 0x18) if width == 8 else (0x08, 0x10)
    kernel.mem_write(gdt + code_selector, struct.pack("<Q", code))
    kernel.mem_write(gdt + data_selector, struct.pack("<Q", data))
    engine.reg_write(ux.UC_X86_REG_CS, code_selector)
    for register in (ux.UC_X86_REG_SS, ux.UC_X86_REG_DS, ux.UC_X86_REG_ES):
        engine.reg_write(register, data_selector)
    process = kernel.get_system_process()
    if process is None or not process.threads:
        raise ValueError("Driver initialization requires a guest System process and thread")
    thread = process.threads[0]
    kernel.set_current_process(process)
    kernel.set_current_thread(thread)
    if width == 8:
        # GS:[0x18] is a kernel pointer. Keeping the stock engine's low user
        # address makes signed pointer checks misidentify the execution mode.
        old_pcr = kernel.gs_addr
        pcr = kernel.mem_map(0x1000, base=0xFFFFF80000000000, tag="emu.kernel.pcr")
        kernel.mem_write(pcr, kernel.mem_read(old_pcr, 0x1000))
        kernel.gs_addr = pcr
        engine.reg_write(ux.UC_X86_REG_GS_BASE, pcr)
        prcb = pcr + 0x180
        tss = kernel.mem_map(0x1000, tag="emu.kernel.tss")
        for offset, pointer in ((0, gdt), (8, tss), (0x18, pcr), (0x20, prcb),
                                (0x30, 0), (0x38, idt), (0x188, thread.address)):
            kernel.mem_write(pcr + offset, struct.pack("<Q", pointer))
        kernel.mem_write(pcr + 0x50, b"\0")  # PASSIVE_LEVEL
        kernel.mem_write(pcr + 0x60, struct.pack("<HH", 1, 1))
        if kernel.kernel_lock_storage is None:
            raise ValueError("Modeled kernel is missing queued spin-lock backing storage")
        # WDK ksamd64.inc PbLockQueue=0x6F0; KSPIN_LOCK_QUEUE is Next, Lock.
        queues = prcb + 0x6F0
        kernel.mem_write(pcr + 0x28, struct.pack("<Q", queues))
        for index in range(17):  # wdm.h LockQueueMaximumLock
            kernel.mem_write(queues + index * 16, struct.pack("<QQ", 0, kernel.kernel_lock_storage + index * 8))
    else:
        pcr = kernel.fs_addr
        prcb = pcr + 0x120
        for offset, pointer in ((0x18, 0), (0x1C, pcr), (0x20, prcb),
                                (0x38, idt), (0x3C, gdt), (0x124, thread.address)):
            kernel.mem_write(pcr + offset, struct.pack("<I", pointer))
        kernel.mem_write(pcr + 0x24, b"\0")
        kernel.mem_write(pcr + 0x14, struct.pack("<I", 1))  # SetMemberCopy, CPU 0.
        kernel.mem_write(pcr + 0x48, struct.pack("<I", 1))  # SetMember.
        kernel.mem_write(pcr + 0x51, b"\0")  # Number.
    kernel.kernel_context_initialized = True
    kernel.kernel_cpu = KernelCpu(kernel)
    return {"cpl": engine.reg_read(ux.UC_X86_REG_CS) & 3,
            "cs": hex(engine.reg_read(ux.UC_X86_REG_CS)),
            "ss": hex(engine.reg_read(ux.UC_X86_REG_SS)),
            "pcr": hex(pcr), "prcb": hex(prcb), "thread": hex(thread.address),
            "queued_spin_locks": 17 if width == 8 else 0,
            "system_pid": process.pid, "cpu_state": kernel.kernel_cpu.initial}
