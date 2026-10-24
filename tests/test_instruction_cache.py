"""Instruction caching must survive overlapping writes and page boundaries."""

import unittest
from emumee.instruction_cache import InstructionCache


class InstructionCacheTests(unittest.TestCase):
    def test_cached_classification_is_invalidated_by_overlapping_write(self):
        memory=bytearray(8192)
        memory[20:22]=b'\x90\x90'
        cache=InstructionCache(lambda start,size:memory[start:start+size])
        self.assertEqual(cache.instruction_info(20,2,8),(b'\x90\x90',0))
        self.assertEqual(cache.instruction_info(20,2,8),(b'\x90\x90',0))
        memory[20:22]=b'\x0f\x31'; cache.invalidate(21,1)
        self.assertEqual(cache.instruction_info(20,2,8),(b'\x0f\x31',8))

    def test_cross_page_classification_and_width_do_not_reuse_stale_flags(self):
        memory=bytearray(8192); memory[4094:4098]=b'\x44\x0f\x22\xc0'
        cache=InstructionCache(lambda start,size:memory[start:start+size])
        self.assertEqual(cache.instruction_info(4094,4,8)[1],5)
        self.assertEqual(cache.instruction_info(4094,4,4)[1],0)
        memory[4096:4098]=b'\x31\xc0'; cache.invalidate(4096,2)
        self.assertEqual(cache.instruction_info(4094,4,8)[0],b'\x44\x0f\x31\xc0')
        self.assertEqual(cache.instruction_info(4094,4,8)[1],0)

    def test_decoded_metadata_obeys_page_eviction_limit(self):
        memory=bytearray(8192); cache=InstructionCache(lambda start,size:memory[start:start+size],pages=1)
        cache.instruction_info(0,1,8); cache.instruction_info(4096,1,8)
        self.assertEqual(set(cache.decoded),{4096})
        memory[0]=0x65
        self.assertEqual(cache.instruction_info(0,1,8),(b'\x65',1))

    def test_invalid_decoder_length_never_becomes_a_large_read(self):
        def read(*_args):
            self.fail("Invalid instruction length reached memory reader")
        cache = InstructionCache(read)
        for size in (0, 16, 0xF1F1F1F1):
            with self.assertRaises(ValueError):
                cache.instruction(0x1000, size)

    def test_cross_page_instruction_and_overlapping_write_invalidation(self):
        memory = bytearray(3 * 4096)
        memory[4094:4100] = b"before"
        cache = InstructionCache(lambda start, size: memory[start:start + size], pages=2)
        self.assertEqual(cache.instruction(4094, 6), b"before")
        memory[4096:4100] = b"POST"
        cache.invalidate(4096, 4)
        self.assertEqual(cache.instruction(4094, 6), b"bePOST")
        self.assertEqual((cache.hits, cache.misses), (1, 3))
        cache.instruction(8192, 2)
        self.assertEqual(len(cache.pages), 2)
        memory[4094:4100] = b"after!"
        cache.invalidate(4094, 6)
        self.assertEqual(cache.instruction(4094, 6), b"after!")
