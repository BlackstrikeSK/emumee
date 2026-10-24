//! Bounded synthetic kernel address placement, separate from object semantics.
use crate::pe::Architecture;
use serde::Serialize;
pub const ENTRY_STACK_SIZE: u64 = 0x100000;
pub const THREAD_STACK_SIZE: u64 = 0x20000;
/// Engine-owned contexts; the independent pure Scheduler retains its 256 limit.
pub const NATIVE_THREAD_LIMIT: u64 = 64;
pub const NATIVE_THREAD_HANDLE_FIRST: u64 = 0x80000000;
pub const NATIVE_THREAD_HANDLE_END: u64 =
    NATIVE_THREAD_HANDLE_FIRST + (NATIVE_THREAD_LIMIT + 1) * 4;
pub fn native_thread_handle_first(architecture: Architecture) -> u64 {
    NATIVE_THREAD_HANDLE_FIRST
        | if architecture == Architecture::X64 {
            0xffffffff00000000
        } else {
            0
        }
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct KernelLayout {
    pub entry_stack: u64,
    pub driver_object: u64,
    pub registry_path: u64,
    pub root_thread: u64,
    pub descriptor_tables: u64,
    pub pcr: u64,
    /// Bounded, separately owned READ/NX loader-metadata arena.
    pub loader_entries: u64,
    pub return_marker: u64,
    child_stacks: u64,
    child_objects: u64,
}
impl KernelLayout {
    pub fn for_architecture(architecture: Architecture) -> Self {
        let (stack, objects, tables, pcr, children, child_objects) = match architecture {
            Architecture::X64 => (
                0xffffa00000000000,
                0xffffa10000000000,
                0xfffff80000100000,
                0xfffff80000000000,
                0xffffa00001000000,
                0xffffa10000100000,
            ),
            Architecture::X86 => (
                0xb0000000, 0xd0000000, 0xffd00000, 0xffdff000, 0xb1000000, 0xd0100000,
            ),
        };
        Self {
            entry_stack: stack,
            driver_object: objects,
            registry_path: objects + 4096,
            root_thread: objects + 8192,
            descriptor_tables: tables,
            pcr,
            loader_entries: if architecture == Architecture::X64 {
                0xffffa10000200000
            } else {
                0xd0200000
            },
            return_marker: if architecture == Architecture::X64 {
                0xfffff80200020000
            } else {
                0x82020000
            },
            child_stacks: children,
            child_objects,
        }
    }
    pub fn thread_stack(self, id: u64) -> Option<u64> {
        if !(2..=NATIVE_THREAD_LIMIT).contains(&id) {
            return None;
        }
        self.child_stacks.checked_add(id * THREAD_STACK_SIZE)
    }
    pub fn thread_object(self, id: u64) -> Option<u64> {
        if id == 1 {
            return Some(self.root_thread);
        }
        if !(2..=NATIVE_THREAD_LIMIT).contains(&id) {
            return None;
        }
        self.child_objects.checked_add(id * 4096)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn system_ranges_are_aligned_bounded_and_separate_for_both_pointer_widths() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let layout = KernelLayout::for_architecture(architecture);
            let floor = if architecture == Architecture::X64 {
                0xffff800000000000
            } else {
                0x80000000
            };
            for base in [
                layout.entry_stack,
                layout.driver_object,
                layout.registry_path,
                layout.root_thread,
                layout.descriptor_tables,
                layout.pcr,
                layout.loader_entries,
            ] {
                assert!(base >= floor);
                assert_eq!(base % 4096, 0);
                if architecture == Architecture::X86 {
                    assert!(base <= u32::MAX as u64);
                }
            }
            assert_eq!(layout.thread_object(1), Some(layout.root_thread));
            assert!(layout.thread_stack(1).is_none());
            assert!(layout.thread_object(65).is_none());
            assert!(layout.thread_stack(2).unwrap() >= layout.entry_stack + ENTRY_STACK_SIZE);
            assert!(layout.thread_object(2).unwrap() >= layout.root_thread + 4096);
            assert!(
                layout.thread_stack(64).unwrap() + THREAD_STACK_SIZE
                    > layout.thread_stack(2).unwrap()
            );
        }
    }
}
