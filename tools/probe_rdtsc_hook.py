"""Harmless check that a Unicorn code hook can replace RDTSC."""

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_EIP


def main() -> None:
    cpu = Uc(UC_ARCH_X86, UC_MODE_32)
    cpu.mem_map(0x1000, 0x1000)
    cpu.mem_write(0x1000, b"\x0f\x31\x90")

    def code(engine, address, size, _user_data):
        if address == 0x1000:
            engine.reg_write(UC_X86_REG_EAX, 0x1234)
            engine.reg_write(UC_X86_REG_EDX, 0x5678)
            engine.reg_write(UC_X86_REG_EIP, address + 2)

    cpu.hook_add(UC_HOOK_CODE, code)
    cpu.emu_start(0x1000, 0x1003)
    print(f"eax={cpu.reg_read(UC_X86_REG_EAX):#x} "
          f"edx={cpu.reg_read(UC_X86_REG_EDX):#x}")


if __name__ == "__main__":
    main()
