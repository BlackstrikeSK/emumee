//! Bounded CRT allocations on the existing guest heap planner. Runtime families
//! own distinct heaps; no host allocator, pointer or libc call reaches the guest.
use super::*;
use emumee_core::heap::HeapError;

#[derive(Clone, Copy)]
enum Operation {
    Allocate,
    Zero,
    Free,
    New,
}
#[derive(Clone, Copy)]
pub(super) struct Call {
    family: usize,
    operation: Operation,
}
#[derive(Default)]
pub(super) struct State {
    heaps: [Option<u64>; 2],
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    let family = match module {
        "msvcrt" => 0,
        "ucrtbase" | "api-ms-win-crt-heap-l1-1-0" => 1,
        _ => return None,
    };
    let name = if family == 1 {
        name.strip_prefix("_o_").unwrap_or(name)
    } else {
        name
    };
    let (operation, count, returns) = match name {
        "malloc" => (Operation::Allocate, 1, T::Pointer),
        "calloc" => (Operation::Zero, 2, T::Pointer),
        "free" => (Operation::Free, 1, T::Void),
        "??2@YAPAXI@Z" if family == 0 => (Operation::New, 1, T::Pointer),
        "??3@YAXPAX@Z" | "??3@YAXPEAX@Z" if family == 0 => (Operation::Free, 1, T::Void),
        _ => return None,
    };
    Some((Call { family, operation }, count, returns))
}
pub(super) fn owns_heap(engine: &Unicorn<Trace>, handle: u64) -> bool {
    engine
        .get_data()
        .apis
        .crt_alloc
        .heaps
        .contains(&Some(handle))
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "CRT allocation requires a user process"
    );
    if matches!(call.operation, Operation::Free) && args[0] == 0 {
        return Ok(0);
    }
    let size = match call.operation {
        Operation::Zero => args[0].checked_mul(args[1]).filter(|n| {
            engine.get_data().architecture != Architecture::X86 || *n <= u32::MAX as u64
        }),
        Operation::New if args[0] == 0 => Some(engine.get_data().architecture.width() as u64),
        _ => Some(args[0]),
    };
    let Some(size) = size else { return Ok(0) };
    let heap = match engine.get_data().apis.crt_alloc.heaps[call.family] {
        Some(heap) => heap,
        None => {
            ensure!(
                !matches!(call.operation, Operation::Free),
                "CRT free has no owned allocation"
            );
            let heap = match engine.get_data_mut().apis.heaps.create(0, 0, 0) {
                Ok(heap) => heap,
                Err(HeapError::Limit) => return Ok(0),
                Err(error) => return Err(error.into()),
            };
            engine.get_data_mut().apis.crt_alloc.heaps[call.family] = Some(heap);
            heap
        }
    };
    let state = &engine.get_data().apis;
    let plan = if matches!(call.operation, Operation::Free) {
        state
            .heaps
            .free(&state.allocations, &state.memory, heap, 0, args[0])
    } else {
        state
            .heaps
            .allocate(&state.allocations, &state.memory, heap, 8, size)
    };
    heap::finish(engine, plan, false)
}
