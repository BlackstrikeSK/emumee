"""Kernel CPU initialization and bounded architectural system-entry transitions.

This is not a Windows syscall dispatcher or a hardware page-table model.
Guest-map permissions remain enforced independently of CR0.WP changes.
"""
from collections import deque
from unicorn import UC_TLB_VIRTUAL, x86_const as ux
from speakeasy.windows.loaders import ApiModuleLoader

EFER, STAR, LSTAR, FMASK = 0xC0000080, 0xC0000081, 0xC0000082, 0xC0000084
BOOT_CR0 = 0x80050033  # PG, AM, WP, NE, ET, MP, PE; paging uses the virtual TLB.


class KernelCpu:
    def __init__(self, kernel):
        self.kernel = kernel
        self.events = deque(maxlen=128)
        self.attempts = 0
        engine = kernel.emu_eng.emu
        engine.ctl_set_tlb_mode(UC_TLB_VIRTUAL)
        # PAE is required by the modeled x64 long mode and x86 NX support.
        engine.reg_write(ux.UC_X86_REG_CR4, engine.reg_read(ux.UC_X86_REG_CR4) | 0x20)
        engine.reg_write(ux.UC_X86_REG_CR0, BOOT_CR0)
        engine.msr_write(EFER, engine.msr_read(EFER) | 0x800)
        if kernel.get_ptr_size() == 8:
            engine.msr_write(EFER, engine.msr_read(EFER) | 1)
            engine.msr_write(STAR, (0x23 << 48) | (0x10 << 32))
            engine.msr_write(FMASK, 0x4700)
        engine.reg_write(ux.UC_X86_REG_EFLAGS, 0x202)
        self.initial = self.state()

    def prepare_run(self, run):
        # Normal lifecycle/System-thread entries start with IF enabled. An IPI
        # enters with maskable interrupts disabled. Resumed contexts bypass
        # preparation and retain their guest-saved flags.
        self.kernel.emu_eng.emu.reg_write(ux.UC_X86_REG_EFLAGS,
                                        0x2 if run.type == "kernel_ipi" else 0x202)

    def state(self):
        engine = self.kernel.emu_eng.emu
        result = {name.lower(): hex(engine.reg_read(getattr(ux, "UC_X86_REG_" + name)))
                  for name in ("CR0", "CR3", "CR4", "CS", "SS", "EFLAGS")}
        result.update({name: hex(engine.msr_read(number)) for name, number in
                       (("efer", EFER), ("star", STAR), ("lstar", LSTAR), ("fmask", FMASK))})
        return result

    def stop(self, row, reason, detail, api=None):
        kernel = self.kernel
        row.update(accepted=False, reason=reason)
        error = kernel.get_error_info(reason, kernel.get_pc())
        kernel.curr_run.error = error.model_copy(update={"context_summary": detail, "api_name": api})
        kernel.on_emu_complete()
        return True

    def instruction(self, address, code):
        index = 0
        while index < len(code) and code[index] in (0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67):
            index += 1
        if self.kernel.get_ptr_size() == 8:
            while index < len(code) and 0x40 <= code[index] <= 0x4F:
                index += 1
        opcode = code[index:]
        names = {b"\x0f\x05": "SYSCALL", b"\x0f\x07": "SYSRET",
                 b"\x0f\x34": "SYSENTER", b"\x0f\x35": "SYSEXIT"}
        name = names.get(opcode)
        if name is None:
            return False
        kernel = self.kernel
        engine = kernel.emu_eng.emu
        self.attempts += 1
        state = self.state()
        row = {"instruction": name, "bytes": code.hex(), "pc": hex(address), "processor": getattr(kernel, "processor_id", 0),
               "state_before": state, "accepted": False}
        self.events.append(row)
        if (0xF0 in code[:index] or name != "SYSCALL" or kernel.get_ptr_size() != 8 or
                engine.msr_read(EFER) & 0x401 != 0x401):
            return self.stop(row, "unsupported_kernel_instruction",
                f"{name} with EFER={state['efer']}: its exception/entry/return delivery is not modeled")
        target = engine.msr_read(LSTAR)
        selector = (engine.msr_read(STAR) >> 32) & 0xFFFC
        # This entry model uses the initialized kernel descriptor pair. Other
        # pairs and noncanonical targets need architectural exception delivery.
        if (selector != 0x10 or engine.reg_read(ux.UC_X86_REG_CS) != 0x10 or
                not (target < (1 << 47) or target >= (1 << 64) - (1 << 47))):
            return self.stop(row, "unsupported_kernel_syscall_state",
                "SYSCALL requires the modeled 64-bit kernel selectors and a canonical LSTAR target")
        symbol = kernel.symbols.get(target)
        module = kernel.get_mod_from_addr(target)
        if (symbol is not None and symbol[1] == "KiSystemCall64" and module is not None and
                isinstance(module.loader, ApiModuleLoader)):
            return self.stop(row, "unsupported_kernel_syscall_dispatch",
                "The modeled Windows service dispatcher has no executable kernel entry; "
                "guest-provided LSTAR entry transitions are supported", "ntoskrnl.KiSystemCall64")
        flags = engine.reg_read(ux.UC_X86_REG_EFLAGS)
        engine.reg_write(ux.UC_X86_REG_RCX, address + len(code))
        engine.reg_write(ux.UC_X86_REG_R11, flags & ~0x10000)
        engine.reg_write(ux.UC_X86_REG_EFLAGS, flags & ~(engine.msr_read(FMASK) | 0x10000))
        engine.reg_write(ux.UC_X86_REG_CS, selector)
        engine.reg_write(ux.UC_X86_REG_SS, selector + 8)
        kernel.set_pc(target)
        row.update(accepted=True, target=hex(target), return_pc=hex(address + len(code)))
        return False

    def report(self):
        return {"initial_state": self.initial, "current_state": self.state(),
                "system_entry_attempts": self.attempts, "entry_tail": list(self.events),
                "scope": "Virtual-TLB kernel mappings and x64 CPL-0 SYSCALL to guest-provided LSTAR entries; "
                         "fresh normal kernel entries enable IF, IPI entries disable it, resumed flags are preserved; "
                         "guest-map permissions remain enforced when CR0.WP changes; "
                         "no physical page-table walk, Windows syscall dispatcher, SYSRET/SYSENTER/SYSEXIT, "
                         "or general architectural exception delivery"}
