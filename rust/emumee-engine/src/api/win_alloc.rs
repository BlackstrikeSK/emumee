//! Win32 Global/Local wrappers, heap validation and address-range predicates.
//! Everything here reuses the existing process heap and private reservation
//! models; no host allocator, host pointer or host probe reaches the guest.
use super::*;
use emumee_core::{heap::PROCESS_HEAP, virtual_memory as vm};

/// Legacy Global/Local bits that modern Windows ignores for a fixed block:
/// MOVEABLE, NOCOMPACT, NODISCARD, ZEROINIT, NOT_BANKED and DDESHARE.
const ALLOC_FLAGS: u64 = 0x2 | 0x10 | 0x20 | 0x40 | 0x1000 | 0x2000;
const MOVEABLE: u64 = 0x2;
const ZEROINIT: u64 = 0x40;
/// IsBadStringPtr scans at most this many characters before stopping explicitly.
const MAX_SCAN: u64 = 1 << 20;

#[derive(Clone, Copy)]
pub(super) enum Call {
    Alloc,
    Free,
    Size,
    Flags,
    Handle,
    Lock,
    Unlock,
    Reallocate,
    Validate,
    RtlSize,
    SetInformation,
    Query,
    AllocExNuma,
    Bad(bool),
    BadString(bool),
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    let heap_set = matches!(
        module,
        "kernel32" | "kernelbase" | "api-ms-win-core-heap-l1-1-0"
    );
    Some(match (module, name) {
        ("kernel32" | "kernelbase", "GlobalAlloc" | "LocalAlloc") => (Call::Alloc, 2, T::Pointer),
        ("kernel32" | "kernelbase", "GlobalFree" | "LocalFree") => (Call::Free, 1, T::Pointer),
        ("kernel32" | "kernelbase", "GlobalSize" | "LocalSize") => (Call::Size, 1, T::Pointer),
        ("kernel32" | "kernelbase", "GlobalFlags" | "LocalFlags") => (Call::Flags, 1, T::U32),
        ("kernel32" | "kernelbase", "GlobalHandle" | "LocalHandle") => {
            (Call::Handle, 1, T::Pointer)
        }
        ("kernel32" | "kernelbase", "GlobalLock" | "LocalLock") => (Call::Lock, 1, T::Pointer),
        ("kernel32" | "kernelbase", "GlobalUnlock" | "LocalUnlock") => (Call::Unlock, 1, T::U32),
        ("kernel32" | "kernelbase", "LocalReAlloc") => (Call::Reallocate, 3, T::Pointer),
        ("kernel32" | "kernelbase", "HeapSetInformation") => (Call::SetInformation, 4, T::U32),
        ("kernel32" | "kernelbase", "VirtualQuery") => (Call::Query, 3, T::Pointer),
        ("kernel32" | "kernelbase", "VirtualAllocExNuma") => (Call::AllocExNuma, 6, T::Pointer),
        ("kernel32" | "kernelbase", "IsBadReadPtr") => (Call::Bad(false), 2, T::U32),
        ("kernel32" | "kernelbase", "IsBadWritePtr") => (Call::Bad(true), 2, T::U32),
        ("kernel32" | "kernelbase", "IsBadStringPtrA") => (Call::BadString(false), 2, T::U32),
        ("kernel32" | "kernelbase", "IsBadStringPtrW") => (Call::BadString(true), 2, T::U32),
        (_, "HeapValidate") if heap_set => (Call::Validate, 3, T::U32),
        ("ntdll", "RtlSizeHeap") => (Call::RtlSize, 3, T::Pointer),
        _ => return None,
    })
}
fn invalid_size(engine: &Unicorn<Trace>) -> u64 {
    match engine.get_data().architecture {
        Architecture::X86 => u32::MAX as u64,
        _ => u64::MAX,
    }
}
/// The size of a live process-heap block, or nothing for every other value.
fn block(engine: &Unicorn<Trace>, handle: u64) -> Option<u64> {
    engine
        .get_data()
        .apis
        .heaps
        .size(PROCESS_HEAP, 0, handle)
        .ok()
}
fn fail(engine: &mut Unicorn<Trace>, error: u32, value: u64) -> Result<u64> {
    engine.get_data_mut().apis.last_error = error;
    Ok(value)
}
fn succeed(engine: &mut Unicorn<Trace>, value: u64) -> Result<u64> {
    engine.get_data_mut().apis.last_error = 0;
    Ok(value)
}
fn accessible(engine: &Unicorn<Trace>, address: u64, size: u64, write: bool) -> bool {
    address != 0
        && address.checked_add(size).is_some()
        && engine
            .get_data()
            .apis
            .memory
            .allows(address, size, if write { P::RW } else { P::READ })
}
fn mbi_size(engine: &Unicorn<Trace>) -> u64 {
    if engine.get_data().architecture == Architecture::X86 {
        28
    } else {
        48
    }
}
/// MEMORY_BASIC_INFORMATION exactly as Windows lays it out, including the two
/// x64 alignment holes, so compiler-produced callers see the size they expect.
fn encode(engine: &Unicorn<Trace>, query: &vm::Query) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(48);
    if engine.get_data().architecture == Architecture::X86 {
        for value in [query.base, query.allocation_base] {
            bytes.extend((value as u32).to_le_bytes());
        }
        bytes.extend(query.allocation_protect.to_le_bytes());
        bytes.extend((query.size as u32).to_le_bytes());
        for value in [query.state, query.protect, query.kind] {
            bytes.extend(value.to_le_bytes());
        }
    } else {
        for value in [query.base, query.allocation_base] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend(query.allocation_protect.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(query.size.to_le_bytes());
        for value in [query.state, query.protect, query.kind] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend(0u32.to_le_bytes());
    }
    bytes
}
/// Stops at the terminator, as Windows does, instead of demanding that the whole
/// character maximum be readable. Work stays bounded by MAX_SCAN characters.
fn bad_string(engine: &Unicorn<Trace>, address: u64, maximum: u64, wide: bool) -> Result<u64> {
    let width = if wide { 2 } else { 1 };
    if address == 0 || maximum == 0 {
        return Ok(1);
    }
    ensure!(
        maximum <= MAX_SCAN,
        "IsBadStringPtr character maximum {maximum} exceeds bounded work"
    );
    for index in 0..maximum {
        let Some(at) = address.checked_add(index * width) else {
            return Ok(1);
        };
        if !accessible(engine, at, width, false) {
            return Ok(1);
        }
        if read(engine, at, width)?.iter().all(|byte| *byte == 0) {
            return Ok(0);
        }
    }
    Ok(0)
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "Win32 allocation APIs are outside the kernel target profile"
    );
    match call {
        Call::Alloc => {
            ensure!(
                args[0] & !ALLOC_FLAGS == 0,
                "Global/Local allocation flags 0x{:x} are not modeled",
                args[0]
            );
            let state = &engine.get_data().apis;
            let plan = state.heaps.allocate(
                &state.allocations,
                &state.memory,
                PROCESS_HEAP,
                if args[0] & ZEROINIT != 0 { 8 } else { 0 },
                args[1],
            );
            let result = heap::finish(engine, plan, true)?;
            if result != 0 {
                return succeed(engine, result);
            }
            Ok(0)
        }
        Call::Free => {
            if args[0] == 0 {
                return Ok(0);
            }
            crt_startup::require_allocation_change(engine, args[0], 1)?;
            let state = &engine.get_data().apis;
            let plan = state
                .heaps
                .free(&state.allocations, &state.memory, PROCESS_HEAP, 0, args[0]);
            heap::finish(engine, plan, true)?;
            // Global/LocalFree return NULL once the block is gone.
            succeed(engine, 0)
        }
        Call::Reallocate => {
            ensure!(
                args[2] & !ALLOC_FLAGS == 0,
                "LocalReAlloc flags 0x{:x} are not modeled",
                args[2]
            );
            crt_startup::require_allocation_change(engine, args[0], 1)?;
            // Without LMEM_MOVEABLE a local block may not be relocated.
            let flags = if args[2] & ZEROINIT != 0 { 8 } else { 0 }
                | if args[2] & MOVEABLE != 0 { 0 } else { 0x10 };
            let state = &engine.get_data().apis;
            let plan = state.heaps.reallocate(
                &state.allocations,
                &state.memory,
                PROCESS_HEAP,
                flags,
                args[0],
                args[1],
            );
            let result = heap::finish(engine, plan, true)?;
            if result != 0 {
                return succeed(engine, result);
            }
            Ok(0)
        }
        Call::Size => match block(engine, args[0]) {
            Some(size) => succeed(engine, size),
            None => fail(engine, 87, 0),
        },
        // A live fixed block has no lock count, discard state or handle table
        // entry, so GlobalFlags reports zero for it and GMEM_INVALID_HANDLE for
        // everything else.
        Call::Flags => match block(engine, args[0]) {
            Some(_) => succeed(engine, 0),
            None => fail(engine, 87, 0x8000),
        },
        // Handles and pointers coincide here: nothing ever relocates.
        Call::Handle | Call::Lock => match block(engine, args[0]) {
            Some(_) => succeed(engine, args[0]),
            None => fail(engine, 6, 0),
        },
        Call::Unlock => match block(engine, args[0]) {
            Some(_) => succeed(engine, 0),
            None => fail(engine, 6, 0),
        },
        Call::Validate => Ok(u64::from(engine.get_data().apis.heaps.validate(
            args[0],
            args[1] as u32,
            args[2],
        ))),
        Call::RtlSize => Ok(engine
            .get_data()
            .apis
            .heaps
            .any_size(args[0], args[1] as u32, args[2])
            .unwrap_or_else(|| invalid_size(engine))),
        // The synthetic heaps carry no compatibility, corruption-termination or
        // resource-optimization state, so a recognized request changes nothing.
        Call::SetInformation => {
            let known = match args[1] {
                0 => args[3] == 4 && accessible(engine, args[2], 4, false),
                1 => args[2] == 0 && args[3] == 0,
                2 => args[3] == 8 && accessible(engine, args[2], 8, false),
                _ => false,
            };
            if !known || (args[0] != 0 && !engine.get_data().apis.heaps.validate(args[0], 0, 0)) {
                return fail(engine, 87, 0);
            }
            succeed(engine, 1)
        }
        Call::Query => {
            let size = mbi_size(engine);
            if args[1] == 0 || args[2] < size {
                return fail(engine, 87, 0);
            }
            if !accessible(engine, args[1], size, true) {
                return fail(engine, 998, 0);
            }
            let state = &engine.get_data().apis;
            let Ok(query) = state.allocations.query(&state.memory, args[0]) else {
                return fail(engine, 87, 0);
            };
            let bytes = encode(engine, &query);
            crate::cpu::write(engine, args[1], &bytes)?;
            succeed(engine, size)
        }
        Call::AllocExNuma => {
            // Only the current-process pseudo handle, at the guest's own width.
            let width = engine.get_data().architecture.width() as u32;
            if args[0] != u64::MAX >> (64 - 8 * width) {
                return fail(engine, 6, 0);
            }
            if args[5] != 0 && args[5] != u32::MAX as u64 {
                return fail(engine, 87, 0);
            }
            allocation::allocate(engine, &args[1..5])
        }
        Call::Bad(write) => Ok(u64::from(
            args[0] == 0 || args[1] == 0 || !accessible(engine, args[0], args[1], write),
        )),
        Call::BadString(wide) => bad_string(engine, args[0], args[1], wide),
    }
}
