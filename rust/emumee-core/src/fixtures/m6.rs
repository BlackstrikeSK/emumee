//! Shared owned-PE scaffolding for the M6 registry, persona and filesystem
//! guest control families.
//!
//! Every M6 control is a harmless generated x86/x64 caller that reaches the
//! modeled exports through a real import table and decides its own outcome: a
//! value the model got wrong raises a breakpoint inside the guest instead of
//! being handed back for a host assertion. One skeleton serves all families, so
//! a family body is only its calls and its expectations.
use super::winhttp::{Arg, call, expect_dword, load, store, write_dword};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;

/// String slots and mutable scratch, as image-relative addresses.
const STRINGS: u64 = 0x2a00;
const STRING_STRIDE: u64 = 0x80;
const SCRATCH: u64 = 0x3400;
const IMAGE_END: u64 = 0x7000;
/// Poison pattern: a model that writes nothing must leave these bytes alone.
pub(super) const POISON: u32 = 0x77777777;

pub(super) struct Probe {
    data: Vec<u8>,
    code: Vec<u8>,
    pub wide: bool,
    pub base: u64,
    pub unicode: bool,
    strings: u64,
    scratch: u64,
    /// Thunk slot for each export, in declaration order. A two-group table has
    /// one null slot between the groups, so export order is not slot order.
    slots: Vec<usize>,
}

/// Encode guest text in the width a family's A/W selection implies.
pub(super) fn encoded(value: &str, unicode: bool, nul: bool) -> Vec<u8> {
    let mut bytes: Vec<u8> = if unicode {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    } else {
        value
            .chars()
            .map(|c| {
                assert!(c.is_ascii(), "narrow fixture text must be ASCII: {value:?}");
                c as u8
            })
            .collect()
    };
    if nul {
        bytes.extend(std::iter::repeat_n(0, if unicode { 2 } else { 1 }));
    }
    bytes
}

impl Probe {
    /// `modules` holds one or two import groups, each a module name and the
    /// exports the family calls. A call index numbers the exports in
    /// declaration order across every group; the null slot a linker places
    /// between two groups is skipped for the caller.
    pub(super) fn new(
        architecture: Architecture,
        unicode: bool,
        modules: &[(&str, Vec<String>)],
    ) -> Self {
        assert!(matches!(modules.len(), 1 | 2));
        let wide = architecture == Architecture::X64;
        let width = if wide { 8usize } else { 4 };
        let base = if wide { 0x140000000u64 } else { 0x400000 };
        let original = api_probe(architecture, ApiFixture::Unsupported);
        let mut data = vec![0; 0x6200];
        data[..0x200].copy_from_slice(&original[..0x200]);
        let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
        let dd = 0x98 + if wide { 112 } else { 96 };
        put32(&mut data, 0x98 + 4, 0x1000);
        put32(&mut data, 0x98 + 8, 0x5000);
        put32(&mut data, 0x98 + 56, IMAGE_END as u32);
        put16(&mut data, 0x98 + 68, 3);
        put16(&mut data, 0x96, 0x22);
        put32(&mut data, table + 8, 0x1000);
        put32(&mut data, table + 16, 0x1000);
        put32(&mut data, table + 40 + 8, 0x5000);
        put32(&mut data, table + 40 + 16, 0x5000);
        put32(&mut data, table + 40 + 20, 0x1200);
        put32(&mut data, dd + 8, 0x2000);
        put32(&mut data, dd + 12, 60);
        // One thunk array serves both groups: the zero slot between them is the
        // first group's null terminator, exactly as a linker would emit it.
        let capacity: usize = modules.iter().map(|(_, names)| names.len() + 1).sum();
        assert!(capacity * width <= 0x100, "import thunks exceed their array");
        let mut slot = 0;
        let mut slots = Vec::new();
        for (group, (module, names)) in modules.iter().enumerate() {
            let descriptor = 0x1200 + group * 20;
            put32(&mut data, descriptor, 0x2180 + (slot * width) as u32);
            // Module names sit past the hint/name table, where an API-set
            // name has room for its full length.
            put32(&mut data, descriptor + 12, 0x2900 + group as u32 * 0x80);
            put32(&mut data, descriptor + 16, 0x2080 + (slot * width) as u32);
            let raw = 0x1b00 + group * 0x80;
            assert!(module.len() < 0x80, "module name does not fit: {module}");
            data[raw..raw + module.len()].copy_from_slice(module.as_bytes());
            for name in names {
                let rva = 0x2300 + slot as u32 * 48;
                for raw in [0x1280, 0x1380] {
                    if wide {
                        put64(&mut data, raw + slot * 8, rva.into());
                    } else {
                        put32(&mut data, raw + slot * 4, rva);
                    }
                }
                let raw = 0x1500 + slot * 48;
                assert!(name.len() + 3 <= 48, "import name does not fit: {name}");
                data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
                slots.push(slot);
                slot += 1;
            }
            slot += 1; // Null-terminate this group's thunk list.
        }
        let mut code = Vec::new();
        if wide {
            // Shadow space plus the longest stack argument list these families use.
            code.extend([0x48, 0x83, 0xec, 0x78]);
        }
        Self {
            data,
            code,
            wide,
            base,
            unicode,
            strings: STRINGS,
            scratch: SCRATCH,
            slots,
        }
    }
    fn write(&mut self, rva: u64, bytes: &[u8]) {
        let raw = (rva - 0xe00) as usize;
        self.data[raw..raw + bytes.len()].copy_from_slice(bytes);
    }
    /// Place a resource directory blob at `rva` and record it as the image's
    /// resource data directory (entry 2). Used by the M7 resource family so a
    /// guest can walk its own `.rsrc` through the real APIs.
    pub(super) fn resources(&mut self, rva: u64, blob: &[u8]) {
        self.write(rva, blob);
        let dd = 0x98 + if self.wide { 112 } else { 96 };
        put32(&mut self.data, dd + 16, rva as u32);
        put32(&mut self.data, dd + 20, blob.len() as u32);
    }
    /// Place guest text in the family's own width and answer its address.
    pub(super) fn string(&mut self, value: &str) -> u64 {
        let bytes = encoded(value, self.unicode, true);
        self.blob(&bytes)
    }
    /// Place narrow guest text regardless of the family's A/W selection.
    pub(super) fn ascii(&mut self, value: &str) -> u64 {
        let bytes = encoded(value, false, true);
        self.blob(&bytes)
    }
    pub(super) fn blob(&mut self, bytes: &[u8]) -> u64 {
        assert!(bytes.len() as u64 <= STRING_STRIDE, "string slot overflow");
        assert!(self.strings + STRING_STRIDE <= SCRATCH, "string slots exhausted");
        let rva = self.strings;
        self.strings += STRING_STRIDE;
        self.write(rva, bytes);
        self.base + rva
    }
    /// Reserve a mutable buffer, 16-byte aligned, and answer its address.
    pub(super) fn scratch(&mut self, bytes: u64) -> u64 {
        let rva = self.scratch;
        self.scratch = (rva + bytes).next_multiple_of(16);
        assert!(self.scratch <= IMAGE_END, "scratch exhausted");
        self.base + rva
    }
    pub(super) fn call(&mut self, index: usize, args: &[Arg]) {
        call(&mut self.code, self.wide, self.base, self.slots[index], args);
    }
    /// Seed the return register after argument marshalling, before a real IAT call.
    pub(super) fn call_seeded(&mut self, index: usize, args: &[Arg], seed: u64) {
        super::winhttp::marshal(&mut self.code, self.wide, args);
        if self.wide {
            self.code.extend([0x48, 0xb8]);
            self.code.extend(seed.to_le_bytes());
        } else {
            self.code.push(0xb8);
            self.code.extend((seed as u32).to_le_bytes());
        }
        call(&mut self.code, self.wide, self.base, self.slots[index], &[]);
    }
    /// Keep the resolved target in a volatile register while seeding RAX/EAX.
    pub(super) fn call_pointer_seeded(&mut self, slot: u64, args: &[Arg], seed: u64) {
        super::winhttp::marshal(&mut self.code, self.wide, args);
        load(&mut self.code, self.wide, slot);
        if self.wide {
            self.code.extend([0x49, 0x89, 0xc3, 0x48, 0xb8]);
            self.code.extend(seed.to_le_bytes());
            self.code.extend([0x41, 0xff, 0xd3]);
        } else {
            self.code.extend([0x89, 0xc2, 0xb8]);
            self.code.extend((seed as u32).to_le_bytes());
            self.code.extend([0xff, 0xd2]);
        }
    }
    /// Call through an object's vtable, exactly as compiled COM code does: the
    /// first argument is the interface pointer and `slot` is the method's
    /// vtable index. The object's vtable pointer is read from the object, then
    /// the slot is called indirectly, so a wrong vtable layout faults here
    /// rather than being papered over.
    pub(super) fn call_vtable(&mut self, slot: usize, args: &[Arg]) {
        super::winhttp::marshal(&mut self.code, self.wide, args);
        let offset = slot * if self.wide { 8 } else { 4 };
        if self.wide {
            // this is in RCX; RAX = [RCX] is the vtable.
            self.code.extend([0x48, 0x8b, 0x01]);
        } else {
            // this was pushed last, so it sits at [ESP]; EAX = [[ESP]].
            self.code.extend([0x8b, 0x04, 0x24]);
            self.code.extend([0x8b, 0x00]);
        }
        if offset < 128 {
            self.code.extend([0xff, 0x50, offset as u8]);
        } else {
            self.code.extend([0xff, 0x90]);
            self.code.extend((offset as u32).to_le_bytes());
        }
    }
    /// The 32-bit return value the guest itself checks.
    pub(super) fn eax(&mut self, value: u32) {
        self.code.push(0x3d);
        self.code.extend(value.to_le_bytes());
        self.code.extend([0x74, 1, 0xcc]);
    }
    /// A pointer-width return value; on x86 only the low half exists.
    pub(super) fn rax(&mut self, value: u64) {
        if self.wide {
            self.code.extend([0x48, 0xba]);
            self.code.extend(value.to_le_bytes());
            self.code.extend([0x48, 0x39, 0xd0, 0x74, 1, 0xcc]);
        } else {
            self.eax(value as u32);
        }
    }
    /// A 64-bit return value. The Windows x86 ABI splits it across EAX and
    /// EDX, so the guest checks both halves there and one register on x64.
    pub(super) fn quad(&mut self, value: u64) {
        if self.wide {
            self.rax(value);
        } else {
            self.eax(value as u32);
            self.code.extend([0x81, 0xfa]);
            self.code.extend(((value >> 32) as u32).to_le_bytes());
            self.code.extend([0x74, 1, 0xcc]);
        }
    }
    /// Call a guest address directly, not through an import thunk, so a guest
    /// can execute bytes it wrote itself.
    pub(super) fn call_absolute(&mut self, address: u64) {
        if self.wide {
            self.code.extend([0x48, 0xb8]);
            self.code.extend(address.to_le_bytes());
        } else {
            self.code.push(0xb8);
            self.code.extend((address as u32).to_le_bytes());
        }
        self.code.extend([0xff, 0xd0]);
    }
    /// Invoke a function pointer returned into a guest-owned pointer slot.
    pub(super) fn call_pointer(&mut self, slot: u64, args: &[Arg]) {
        super::winhttp::marshal(&mut self.code, self.wide, args);
        load(&mut self.code, self.wide, slot);
        self.code.extend([0xff, 0xd0]);
    }
    /// A returned value must be non-zero without the guest naming it.
    pub(super) fn nonzero(&mut self) {
        self.code.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
    }
    /// A returned handle must be neither null nor the all-ones failure, so a
    /// failed open cannot pass for an opened file.
    pub(super) fn opened(&mut self) {
        self.nonzero();
        self.code.extend([0x83, 0xf8, 0xff, 0x75, 1, 0xcc]);
    }
    pub(super) fn dword(&mut self, address: u64, value: u32) {
        expect_dword(&mut self.code, self.wide, address, value);
    }
    /// The word at `address` must differ from `value`. Used where a model
    /// writes a figure the guest cannot predict — a host-seeded timestamp — so
    /// the control proves the output was written without asserting the clock.
    pub(super) fn dword_not(&mut self, address: u64, value: u32) {
        load(&mut self.code, self.wide, address);
        self.code.push(0x3d);
        self.code.extend(value.to_le_bytes());
        self.code.extend([0x75, 1, 0xcc]);
    }
    pub(super) fn qword(&mut self, address: u64, value: u64) {
        self.dword(address, value as u32);
        self.dword(address + 4, (value >> 32) as u32);
    }
    pub(super) fn set_dword(&mut self, address: u64, value: u32) {
        write_dword(&mut self.code, self.wide, address, value);
    }
    pub(super) fn set_qword(&mut self, address: u64, value: u64) {
        self.set_dword(address, value as u32);
        self.set_dword(address + 4, (value >> 32) as u32);
    }
    /// Store the pointer-width return value for use as a later argument.
    pub(super) fn save(&mut self, address: u64) {
        store(&mut self.code, self.wide, address);
    }

    /// Fill a low guest arena with actual CPU stores, preserving nonvolatile DI.
    /// REP STOSD keeps large canary arenas from inflating the fixture's code.
    pub(super) fn fill_words(&mut self, address: u64, words: u32, value: u32) {
        assert!(address <= u32::MAX as u64);
        self.code.extend([0x57, 0xbf]);
        self.code.extend((address as u32).to_le_bytes());
        self.code.push(0xb9);
        self.code.extend(words.to_le_bytes());
        self.code.push(0xb8);
        self.code.extend(value.to_le_bytes());
        self.code.extend([0xfc, 0xf3, 0xab, 0x5f]);
    }
    /// Follow a pointer a model wrote: read the pointer stored at `address`,
    /// then copy the pointer-width value `offset` bytes into the structure it
    /// addresses into `target`. This is how a control walks a linked structure
    /// a model published on the guest heap, whose address it cannot predict.
    pub(super) fn indirect(&mut self, address: u64, offset: u64, target: u64) {
        self.pointer_into_accumulator(address);
        if self.wide {
            // mov rax, [rax + offset]
            self.code.extend([0x48, 0x8b, 0x80]);
        } else {
            self.code.extend([0x8b, 0x80]);
        }
        self.code.extend((offset as u32).to_le_bytes());
        store(&mut self.code, self.wide, target);
    }
    /// The word `offset` bytes into the structure addressed by the pointer at
    /// `address` must equal `value`.
    pub(super) fn indirect_dword(&mut self, address: u64, offset: u64, value: u32) {
        self.pointer_into_accumulator(address);
        // mov eax, [rax/eax + offset]
        self.code.extend([0x8b, 0x80]);
        self.code.extend((offset as u32).to_le_bytes());
        self.code.push(0x3d);
        self.code.extend(value.to_le_bytes());
        self.code.extend([0x74, 1, 0xcc]);
    }
    /// Load a whole pointer from `address` into the accumulator.
    fn pointer_into_accumulator(&mut self, address: u64) {
        if self.wide {
            self.code.extend([0x48, 0xa1]);
            self.code.extend(address.to_le_bytes());
        } else {
            self.code.push(0xa1);
            self.code.extend((address as u32).to_le_bytes());
        }
    }
    pub(super) fn poison(&mut self, address: u64, dwords: u64) {
        for index in 0..dwords {
            self.set_dword(address + index * 4, POISON);
        }
    }
    pub(super) fn intact(&mut self, address: u64, dwords: u64) {
        for index in 0..dwords {
            self.dword(address + index * 4, POISON);
        }
    }
    /// Assert guest text at `address`, including its terminator and the poisoned
    /// word beyond it, so an over-long write cannot pass.
    pub(super) fn text(&mut self, address: u64, value: &str) {
        let bytes = encoded(value, self.unicode, true);
        self.check(address, &bytes, POISON.to_le_bytes()[0]);
        self.dword(address + bytes.len().div_ceil(4) as u64 * 4, POISON);
    }
    pub(super) fn ascii_text(&mut self, address: u64, value: &str) {
        let bytes = encoded(value, false, true);
        self.check(address, &bytes, POISON.to_le_bytes()[0]);
        self.dword(address + bytes.len().div_ceil(4) as u64 * 4, POISON);
    }
    /// Assert exact bytes, padding the final partial word with `padding`.
    pub(super) fn check(&mut self, address: u64, bytes: &[u8], padding: u8) {
        for (index, chunk) in bytes.chunks(4).enumerate() {
            let mut value = [padding; 4];
            value[..chunk.len()].copy_from_slice(chunk);
            self.dword(address + index as u64 * 4, u32::from_le_bytes(value));
        }
    }
    /// Stop the guest here. A family whose contract is an explicit refusal must
    /// never reach this instruction.
    pub(super) fn unreachable(&mut self) {
        self.code.push(0xcc);
    }
    /// The guest's own entry return. A contained control reports success as 1,
    /// which is what the replay verifier requires of a successful entry return.
    pub(super) fn finish(mut self) -> Vec<u8> {
        self.code.push(0xb8);
        self.code.extend(1u32.to_le_bytes());
        if self.wide {
            self.code.extend([0x48, 0x83, 0xc4, 0x78]);
        }
        self.code.push(0xc3);
        assert!(
            self.code.len() < 0x1000,
            "M6 generated code exceeded its owned text section: {}",
            self.code.len()
        );
        let code = std::mem::take(&mut self.code);
        self.data[0x200..0x200 + code.len()].copy_from_slice(&code);
        self.data
    }
}
