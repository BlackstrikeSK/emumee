"""Conservative fallback for common AVX vector moves missing in Unicorn.

Only the decoded operations below are handled. An unknown instruction remains
an invalid guest instruction instead of being skipped or executed on the host.
"""

from __future__ import annotations

from collections import Counter

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from unicorn import UC_HOOK_INSN_INVALID, UC_PROT_READ, UC_PROT_WRITE
from unicorn import x86_const as ux


_MASK128 = (1 << 128) - 1
_MASK256 = (1 << 256) - 1
_MOVES = frozenset(("vmovdqa", "vmovdqu", "vmovntdq"))


class AVXFallback:
    def __init__(self, pointer_size: int):
        self.pointer_size = pointer_size
        self.decoder = Cs(CS_ARCH_X86, CS_MODE_64 if pointer_size == 8
                          else CS_MODE_32)
        self.decoder.detail = True
        self.counts = Counter()
        self.read_guard = None
        self.write_guard = None
        self.hook = None

    def attach(self, engine) -> None:
        self.hook = engine.hook_add(UC_HOOK_INSN_INVALID, self.handle)

    def _register(self, engine, instruction, register: int) -> int | None:
        name = instruction.reg_name(register).upper()
        if not name.startswith(("XMM", "YMM")):
            return None
        value = getattr(ux, "UC_X86_REG_" + name, None)
        if value is None:
            return None
        return engine.reg_read(value)

    @staticmethod
    def _vector_id(instruction, register: int, prefix: str) -> int | None:
        name = instruction.reg_name(register).upper()
        if not name.startswith(prefix) or not name[len(prefix):].isdigit():
            return None
        index = int(name[len(prefix):])
        if index >= 16:
            return None
        return getattr(ux, "UC_X86_REG_" + name, None)

    def _permitted(self, engine, address: int, size: int, permission: int) -> bool:
        if size <= 0 or address < 0 or address + size > 1 << (self.pointer_size * 8):
            return False
        cursor, end = address, address + size
        try:
            regions = engine.mem_regions()
        except Exception:
            return False
        while cursor < end:
            match = next(((begin, last, flags) for begin, last, flags in regions
                          if begin <= cursor <= last), None)
            if match is None or not match[2] & permission:
                return False
            cursor = min(end, match[1] + 1)
        return True

    def _address(self, engine, instruction, operand) -> int | None:
        mem = operand.mem
        if mem.segment:
            return None
        address = int(mem.disp)
        for register, multiplier in ((mem.base, 1), (mem.index, mem.scale)):
            if not register:
                continue
            name = instruction.reg_name(register).upper()
            if name == "RIP":
                value = instruction.address + instruction.size
            elif name == "EIP":
                value = instruction.address + instruction.size
            elif name in ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                          "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                          "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"):
                value = engine.reg_read(getattr(ux, "UC_X86_REG_" + name))
            else:
                return None
            address += value * multiplier
        return address & ((1 << (self.pointer_size * 8)) - 1)

    def _vector_move(self, engine, instruction) -> bool:
        if len(instruction.operands) != 2:
            return False
        destination, source = instruction.operands
        if destination.size not in (16, 32) or source.size != destination.size:
            return False
        size = destination.size
        if destination.type == X86_OP_MEM and source.type == X86_OP_REG:
            register = self._vector_id(instruction, source.reg,
                                       "YMM" if size == 32 else "XMM")
            address = self._address(engine, instruction, destination)
            if register is None or address is None:
                return False
            if instruction.mnemonic != "vmovdqu" and address % size:
                return False
            if not self._permitted(engine, address, size, UC_PROT_WRITE):
                return False
            if self.write_guard is not None and not self.write_guard(address, size):
                return False
            engine.mem_write(address, int(engine.reg_read(register)).to_bytes(size, "little"))
            return True
        if (instruction.mnemonic != "vmovntdq" and destination.type == X86_OP_REG
                and source.type == X86_OP_MEM):
            register = self._vector_id(instruction, destination.reg,
                                       "YMM" if size == 32 else "XMM")
            address = self._address(engine, instruction, source)
            if register is None or address is None:
                return False
            if instruction.mnemonic == "vmovdqa" and address % size:
                return False
            if not self._permitted(engine, address, size, UC_PROT_READ):
                return False
            if self.read_guard is not None and not self.read_guard(address, size):
                return False
            engine.reg_write(register, int.from_bytes(engine.mem_read(address, size), "little"))
            return True
        return False

    def _insert_lane(self, engine, instruction) -> bool:
        operands = instruction.operands
        if (len(operands) != 4 or operands[0].type != X86_OP_REG or
                operands[1].type != X86_OP_REG or
                operands[2].type != X86_OP_REG or
                operands[3].type != X86_OP_IMM or
                operands[0].size != 32 or operands[1].size != 32 or
                operands[2].size != 16):
            return False
        dest = self._vector_id(instruction, operands[0].reg, "YMM")
        source = self._vector_id(instruction, operands[1].reg, "YMM")
        lane = self._vector_id(instruction, operands[2].reg, "XMM")
        if None in (dest, source, lane):
            return False
        original = int(engine.reg_read(source)) & _MASK256
        inserted = int(engine.reg_read(lane)) & _MASK128
        if operands[3].imm & 1:
            result = (original & _MASK128) | (inserted << 128)
        else:
            result = (original & (_MASK128 << 128)) | inserted
        engine.reg_write(dest, result)
        return True

    def _zero_upper(self, engine, instruction) -> bool:
        if instruction.operands:
            return False
        for index in range(16 if self.pointer_size == 8 else 8):
            register = getattr(ux, f"UC_X86_REG_YMM{index}")
            engine.reg_write(register, int(engine.reg_read(register)) & _MASK128)
        return True

    def observe_instruction(self, engine, address: int, size: int, *, code=None) -> None:
        # Unicorn accepts VZEROUPPER on this CPU model but leaves YMM upper
        # lanes unchanged. The existing guest instruction hook calls this
        # before execution; the engine's accepted instruction then completes.
        if size not in (3, 4):
            return
        code = bytes(engine.mem_read(address, size)) if code is None else code
        if code not in (b"\xc5\xf8\x77", b"\xc4\xe1\x78\x77"):
            return
        for index in range(16 if self.pointer_size == 8 else 8):
            register = getattr(ux, f"UC_X86_REG_YMM{index}")
            engine.reg_write(register, int(engine.reg_read(register)) & _MASK128)
        self.counts["vzeroupper"] += 1

    def handle(self, engine, _user_data) -> bool:
        pc_reg = ux.UC_X86_REG_RIP if self.pointer_size == 8 else ux.UC_X86_REG_EIP
        pc = engine.reg_read(pc_reg)
        try:
            # A VEX prefix is necessary but not sufficient. The decoder and
            # exact operand shapes below decide whether emulation is allowed.
            prefix = engine.mem_read(pc, 1)[0]
            if prefix not in (0xC4, 0xC5):
                return False
            available = min(15, 0x1000 - (pc & 0xFFF))
            code = engine.mem_read(pc, available)
            instruction = next(self.decoder.disasm(code, pc, count=1), None)
            if instruction is None:
                return False
            if instruction.mnemonic == "vinsertf128":
                handled = self._insert_lane(engine, instruction)
            elif instruction.mnemonic in _MOVES:
                handled = self._vector_move(engine, instruction)
            elif instruction.mnemonic == "vzeroupper":
                handled = self._zero_upper(engine, instruction)
            else:
                return False
            if not handled:
                return False
            engine.reg_write(pc_reg, pc + instruction.size)
            self.counts[instruction.mnemonic] += 1
            return True
        except Exception:
            return False
