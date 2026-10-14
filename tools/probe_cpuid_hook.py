"""Harmless check of the installed Unicorn CPUID hook's override semantics."""

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_INSN
from unicorn.x86_const import (UC_X86_INS_CPUID, UC_X86_REG_EAX,
                               UC_X86_REG_EBX)


def main() -> None:
    for handled in (0, 1):
        cpu = Uc(UC_ARCH_X86, UC_MODE_32)
        cpu.mem_map(0x1000, 0x1000)
        cpu.mem_write(0x1000, b"\x0f\xa2\x90")
        cpu.reg_write(UC_X86_REG_EAX, 0)

        def cpuid(engine, _user_data):
            engine.reg_write(UC_X86_REG_EAX, 0x1234)
            engine.reg_write(UC_X86_REG_EBX, 0x5678)
            return handled

        cpu.hook_add(UC_HOOK_INSN, cpuid, None, 1, 0, UC_X86_INS_CPUID)
        cpu.emu_start(0x1000, 0x1003)
        print(f"handled={handled} eax={cpu.reg_read(UC_X86_REG_EAX):#x} "
              f"ebx={cpu.reg_read(UC_X86_REG_EBX):#x}")


if __name__ == "__main__":
    main()
