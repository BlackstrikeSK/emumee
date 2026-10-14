"""Harmless Unicorn probes for the bounded AVX instruction fallback."""

from __future__ import annotations

import unittest

from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_32, UC_MODE_64,
                     UC_PROT_READ, Uc, UcError)
from unicorn.x86_const import (UC_X86_REG_ECX, UC_X86_REG_R9, UC_X86_REG_RCX,
                               UC_X86_REG_XMM0, UC_X86_REG_YMM0)

from emumee.avx_fallback import AVXFallback


class AVXFallbackTests(unittest.TestCase):
    def engine(self, bits: int, code: bytes):
        engine = Uc(UC_ARCH_X86, UC_MODE_64 if bits == 64 else UC_MODE_32)
        engine.mem_map(0x1000, 0x1000)
        engine.mem_write(0x1000, code)
        engine.mem_map(0x2000, 0x1000)
        engine.reg_write(UC_X86_REG_RCX if bits == 64 else UC_X86_REG_ECX,
                         0x2000)
        fallback = AVXFallback(bits // 8)
        fallback.attach(engine)
        engine.hook_add(UC_HOOK_CODE,
                        lambda uc, address, size, _data:
                        fallback.observe_instruction(uc, address, size))
        return engine, fallback

    def test_insert_store_and_zero_upper_x86_x64(self):
        # VINSERTF128 ymm0,ymm0,xmm0,1; VMOVDQA [rcx],ymm0; VZEROUPPER.
        code = bytes.fromhex("c4 e3 7d 18 c0 01 c5 fd 7f 01 c5 f8 77")
        pattern = bytes(range(16))
        for bits in (32, 64):
            with self.subTest(bits=bits):
                engine, fallback = self.engine(bits, code)
                engine.reg_write(UC_X86_REG_XMM0, int.from_bytes(pattern, "little"))
                engine.emu_start(0x1000, 0x1000 + len(code))
                self.assertEqual(bytes(engine.mem_read(0x2000, 32)), pattern * 2)
                self.assertEqual(engine.reg_read(UC_X86_REG_YMM0),
                                 int.from_bytes(pattern, "little"))
                self.assertEqual(dict(fallback.counts),
                                 {"vinsertf128": 1, "vmovdqa": 1,
                                  "vzeroupper": 1})

    def test_unaligned_move_and_load(self):
        # VMOVDQU ymm0,[rcx]; VMOVDQU [rcx+0x20],ymm0.
        code = bytes.fromhex("c5 fe 6f 01 c5 fe 7f 41 20")
        engine, fallback = self.engine(64, code)
        engine.reg_write(UC_X86_REG_RCX, 0x2001)
        pattern = bytes(range(32))
        engine.mem_write(0x2001, pattern)
        engine.emu_start(0x1000, 0x1000 + len(code))
        self.assertEqual(bytes(engine.mem_read(0x2021, 32)), pattern)
        self.assertEqual(fallback.counts["vmovdqu"], 2)

    def test_indexed_move_and_non_temporal_store(self):
        indexed = bytes.fromhex("c4 a1 7e 7f 84 09 00 ff ff ff")
        non_temporal = bytes.fromhex("c5 fd e7 01")
        pattern = bytes(range(32))
        engine, fallback = self.engine(64, indexed + non_temporal)
        engine.reg_write(UC_X86_REG_R9, 0x120)
        engine.reg_write(UC_X86_REG_YMM0, int.from_bytes(pattern, "little"))
        engine.emu_start(0x1000, 0x1000 + len(indexed + non_temporal))
        self.assertEqual(bytes(engine.mem_read(0x2020, 32)), pattern)
        self.assertEqual(bytes(engine.mem_read(0x2000, 32)), pattern)
        self.assertEqual(dict(fallback.counts),
                         {"vmovdqu": 1, "vmovntdq": 1})

    def test_guard_and_page_permissions_deny_store(self):
        code = bytes.fromhex("c5 fd 7f 01")  # VMOVDQA [rcx],ymm0
        for denial in ("owner", "permission"):
            with self.subTest(denial=denial):
                engine, fallback = self.engine(64, code)
                engine.reg_write(UC_X86_REG_YMM0, int.from_bytes(b"A" * 32,
                                                                 "little"))
                if denial == "owner":
                    fallback.write_guard = lambda _address, _size: False
                else:
                    engine.mem_protect(0x2000, 0x1000, UC_PROT_READ)
                with self.assertRaises(UcError):
                    engine.emu_start(0x1000, 0x1000 + len(code))
                self.assertEqual(bytes(engine.mem_read(0x2000, 32)), b"\0" * 32)
                self.assertEqual(dict(fallback.counts), {})

    def test_other_avx_instruction_remains_invalid(self):
        engine, fallback = self.engine(64, bytes.fromhex("c5 fd ef c0"))
        with self.assertRaises(UcError):
            engine.emu_start(0x1000, 0x1004)
        self.assertEqual(dict(fallback.counts), {})


if __name__ == "__main__":
    unittest.main()
