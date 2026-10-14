"""Harmless check of the installed CPU engine's XGETBV behavior."""

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX


def main() -> None:
    cpu = Uc(UC_ARCH_X86, UC_MODE_64)
    cpu.mem_map(0x1000, 0x1000)
    cpu.mem_write(0x1000, b"\x31\xc9\x0f\x01\xd0\x90")
    try:
        cpu.emu_start(0x1000, 0x1006)
    except UcError as exc:
        print(f"xgetbv failed: {exc}")
        return
    print(f"xcr0={cpu.reg_read(UC_X86_REG_EDX):#x}:"
          f"{cpu.reg_read(UC_X86_REG_EAX):#x}")


if __name__ == "__main__":
    main()
