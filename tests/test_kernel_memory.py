"""Native CPU probes for bounded kernel copies, fills and page permissions."""
import json
import struct
import tempfile
import unittest
from pathlib import Path
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_runtime import runtime_driver


def memory_probe(machine, name, mode):
    x64 = machine == 0x8664
    base = 0x140000000 if x64 else 0x400000
    destination = base + (0x1180 if mode == 'readonly' else 0x2FFE if mode == 'boundary' else 0x2302 if mode == 'overlap' else 0x2380)
    source = base + 0x2300
    count = 0 if mode == 'empty' else 0x8000001 if mode == 'large' else 4
    if mode == 'empty': destination = source = 0
    if mode == 'unreadable': source = 0xDEADBEEF
    if name in ('RtlMoveMemory','RtlCopyMemory','memcpy','memmove'):
        args = [destination, source, count]
    elif name == 'memset': args = [destination, 0x1FF, count]
    elif name == 'RtlFillMemory': args = [destination, count, 0x1FF]
    else: args = [destination, count]
    tail = b'\x31\xc0' if mode in ('empty','readonly','boundary','large','unreadable') else b'\xa1' + (base + (0x2300 if mode == 'overlap' else 0x2380)).to_bytes(8 if x64 else 4,'little')
    writes = [(0x2300, b'abcdefgh'), (0x2380, b'\xcc' * 16)]
    if mode == 'boundary': writes.append((0x2FFE, b'\xcc\xcc'))
    data = bytearray(runtime_driver(machine, [name], [(0,args,name in ('memcpy','memmove','memset'))], writes, tail=tail))
    if mode == 'boundary':
        # Explicitly map a read-only successor; upstream allocations can occupy
        # the page after a two-section x86 image, so absence is not assured.
        section = 0x98 + (0xF0 if x64 else 0xE0) + 80
        struct.pack_into('<H',data,0x86,3)
        struct.pack_into('<I',data,0x98+56,0x4000)
        struct.pack_into('<8sIIIIIIHHI',data,section,b'.ro\0\0\0\0\0',0x1000,0x3000,0x200,len(data),0,0,0,0,0x40000040)
        data.extend(bytes(0x200))
    return bytes(data)


def repeat_probe(machine):
    x64 = machine == 0x8664
    base = 0x140000000 if x64 else 0x400000
    code = bytearray(bytes.fromhex("41ba04000000") if x64 else bytes.fromhex("bb04000000"))
    loop = len(code)
    code.extend((b"\x48\xbe" + struct.pack("<Q", base + 0x2300) + b"\x48\xbf" + struct.pack("<Q", base + 0x2400)) if x64
                else b"\xbe" + struct.pack("<I", base + 0x2300) + b"\xbf" + struct.pack("<I", base + 0x2400))
    code.extend(bytes.fromhex("b980000000f3a4") + (bytes.fromhex("41ffca") if x64 else bytes.fromhex("4b")))
    code.extend(b"\x75" + bytes([(loop - len(code) - 2) & 255]) + bytes.fromhex("31c0"))
    return runtime_driver(machine, ["KeGetCurrentIrql"], [],
        [(0x2300, bytes(range(128))), (0x2400, b"\xcc" * 128)], tail=bytes(code))


class KernelMemoryTests(unittest.TestCase):
    def test_repeat_copy_keeps_native_bytes_budget_and_cycles_without_false_branches(self):
        for machine in (0x14C, 0x8664):
            for budget in (64, 2000):
                with self.subTest(machine=machine, budget=budget), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    data = repeat_probe(machine)
                    persona = load_persona(None)
                    result = run_driver(data, inspect_pe(data, "repeat.sys"), persona, root, 5, budget)
                    report = json.loads((root / "engine-report.json").read_text())
                    self.assertFalse(any(edge["from"] == edge["to"] for edge in report["control_flow_tail"]))
                    self.assertTrue(report["instruction_repetitions"]["charged_to_instruction_budget"])
                    initial_tsc = persona["uptime_ms"] * 1000 * persona["cpu"]["base_mhz"]
                    self.assertEqual(report["virtual_tsc"] - initial_tsc, result["instruction_count"] * 100)
                    item = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000")
                    copied = (root / "artifacts" / item["file"]).read_bytes()[0x400:0x480]
                    if budget == 64:
                        self.assertIsNone(result["guest_entry_return"])
                        self.assertTrue(result["instruction_limit_reached"])
                        self.assertEqual(result["instruction_count"], 64)
                        prefix = copied.index(0xCC)
                        self.assertTrue(0 < prefix < 128)
                        self.assertEqual(copied, bytes(range(prefix)) + b"\xcc" * (128 - prefix))
                    else:
                        self.assertEqual(result["errors"], [])
                        self.assertEqual(result["guest_entry_return"], 0)
                        self.assertEqual(copied, bytes(range(128)))
                        self.assertEqual(report["instruction_repetitions"]["consecutive_rep_movsb_iterations"], 512)

    def test_real_cpu_copy_fill_zero_and_cdecl(self):
        for machine in (0x14C,0x8664):
            for name in ('RtlMoveMemory','RtlCopyMemory','RtlFillMemory','RtlZeroMemory','memcpy','memmove','memset'):
                for mode in ('success','readonly','boundary','empty','large'):
                    with self.subTest(machine=machine,name=name,mode=mode), tempfile.TemporaryDirectory() as directory:
                        data = memory_probe(machine,name,mode)
                        result = run_driver(data, inspect_pe(data,'memory.sys'),load_persona(None),Path(directory),5,2000)
                        if mode in ('readonly','boundary','large'):
                            self.assertTrue(result['errors'],result)
                            self.assertIsNone(result['guest_entry_return'])
                            self.assertEqual(result['driver_image_changes']['changed_pages'],0)
                        else:
                            self.assertEqual(result['errors'],[],result)
                            expected = 0 if mode == 'empty' or name == 'RtlZeroMemory' else 0xFFFFFFFF if name in ('memset','RtlFillMemory') else int.from_bytes(b'abcd','little')
                            self.assertEqual(result['guest_entry_return'],expected)

    def test_overlapping_moves_and_invalid_read_keep_exact_bytes(self):
        for machine in (0x14C,0x8664):
            for name in ('RtlMoveMemory','memmove'):
                for mode in ('overlap','unreadable'):
                    with self.subTest(machine=machine,name=name,mode=mode), tempfile.TemporaryDirectory() as directory:
                        data = memory_probe(machine,name,mode)
                        result = run_driver(data,inspect_pe(data,'memory.sys'),load_persona(None),Path(directory),5,2000)
                        if mode == 'unreadable':
                            self.assertTrue(result['errors'])
                            self.assertEqual(result['driver_image_changes']['changed_pages'],0)
                        else:
                            self.assertEqual(result['errors'],[])
                            self.assertEqual(result['guest_entry_return'],int.from_bytes(b'abab','little'))
                            item = next(item for item in result['artifacts'] if item['source'] == 'modified_driver_image:0x2000')
                            self.assertEqual((Path(directory)/'artifacts'/item['file']).read_bytes()[0x300:0x308],b'ababcdgh')


if __name__ == '__main__': unittest.main(verbosity=2)
