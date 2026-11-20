//! M6 forced section unmap control family. `NtUnmapViewOfSection` is the first
//! step of process hollowing and RunPE, so it is modeled and observed rather
//! than refused: the guest removes a mapped image from its own space and from a
//! suspended child's space, and the addresses that are not a mapped section's
//! own base are refused.
use super::m6::Probe;
use super::winhttp::Arg::{Memory as M, Value as V};
use crate::pe::Architecture;

#[derive(Clone, Copy, Debug)]
pub enum M6UnmapFixture {
    /// The caller unmaps one of its own mapped images.
    SelfImage,
    /// An interior address, a private reservation, free memory and a handle
    /// without the required access are all refused.
    NotMapped,
    /// A parent rips out a suspended child's primary image: the hollowing
    /// signature, which the run report carries.
    Hollow,
}
/// STATUS_NOT_MAPPED_VIEW, STATUS_INVALID_HANDLE and STATUS_PROCESS_IS_TERMINATING.
const NOT_MAPPED: u32 = 0xc000_0019;
const INVALID_HANDLE: u32 = 0xc000_0008;
const TERMINATING: u32 = 0xc000_010a;

const MODULE_HANDLE: usize = 0;
const CURRENT_PROCESS: usize = 1;
const VIRTUAL_ALLOC: usize = 2;
const VIRTUAL_FREE: usize = 3;
const CREATE_PROCESS: usize = 4;
const TERMINATE: usize = 5;
const LAST_ERROR: usize = 6;
const NT_UNMAP: usize = 7;
const ZW_UNMAP: usize = 8;

fn imports() -> [(&'static str, Vec<String>); 2] {
    [
        (
            "kernel32.dll",
            vec![
                "GetModuleHandleA".into(),
                "GetCurrentProcess".into(),
                "VirtualAlloc".into(),
                "VirtualFree".into(),
                "CreateProcessA".into(),
                "TerminateProcess".into(),
                "GetLastError".into(),
            ],
        ),
        (
            "ntdll.dll",
            vec![
                "NtUnmapViewOfSection".into(),
                "ZwUnmapViewOfSection".into(),
            ],
        ),
    ]
}

/// The suspended child a hollowing control creates. It is never resumed, so its
/// own code never runs; it only has to be a parseable same-architecture image.
pub fn m6_unmap_child(architecture: Architecture) -> Vec<u8> {
    Probe::new(
        architecture,
        false,
        &[("kernel32.dll", vec!["GetLastError".into()])],
    )
    .finish()
}

pub fn m6_unmap_probe(architecture: Architecture, kind: M6UnmapFixture) -> Vec<u8> {
    use M6UnmapFixture as K;
    let mut p = Probe::new(architecture, false, &imports());
    // Parent and child share a preferred base in their own address spaces.
    let image_base = p.base;
    let kernel32 = p.ascii("kernel32.dll");
    let child_path = p.ascii(r"C:\emumee\child.exe");
    let saved = p.scratch(64);
    let startup = p.scratch(128);
    let information = p.scratch(64);
    p.call(CURRENT_PROCESS, &[]);
    p.save(saved);
    match kind {
        K::SelfImage => {
            p.call(MODULE_HANDLE, &[V(kernel32)]);
            p.nonzero();
            p.save(saved + 8);
            // Unlike image retirement this runs no detach and respects no
            // lifecycle phase: the mapped section is removed whole. It is the
            // last call this control makes, because the import thunks it would
            // use next live inside the image it just removed.
            p.call(NT_UNMAP, &[M(saved), M(saved + 8)]);
            p.eax(0);
        }
        K::NotMapped => {
            // An interior address of a mapped image is not that section's own
            // base, in either spelling.
            for (index, address) in [
                (NT_UNMAP, image_base + 0x1000),
                (ZW_UNMAP, image_base + 0x2000),
            ] {
                p.call(index, &[M(saved), V(address)]);
                p.eax(NOT_MAPPED);
            }
            // A private reservation is not a mapped section either.
            p.call(VIRTUAL_ALLOC, &[V(0), V(0x1000), V(0x3000), V(4)]);
            p.nonzero();
            p.save(saved + 8);
            for index in [NT_UNMAP, ZW_UNMAP] {
                p.call(index, &[M(saved), M(saved + 8)]);
                p.eax(NOT_MAPPED);
            }
            p.call(VIRTUAL_FREE, &[M(saved + 8), V(0), V(0x8000)]);
            p.eax(1);
            // Neither is free memory.
            p.call(NT_UNMAP, &[M(saved), V(0x3000_0000)]);
            p.eax(NOT_MAPPED);
            // A handle that was never issued cannot name an address space.
            for index in [NT_UNMAP, ZW_UNMAP] {
                p.call(index, &[V(0x1234), V(image_base)]);
                p.eax(INVALID_HANDLE);
            }
            // None of the refusals removed anything: the modules a refused
            // request named are still mapped.
            p.call(MODULE_HANDLE, &[V(kernel32)]);
            p.nonzero();
            p.call(MODULE_HANDLE, &[V(0)]);
            p.rax(image_base);
        }
        K::Hollow => {
            // CREATE_SUSPENDED: the child is parked before its own entry runs,
            // which is exactly the state a replacement loader wants.
            p.call(
                CREATE_PROCESS,
                &[
                    V(child_path),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(4),
                    V(0),
                    V(0),
                    V(startup),
                    V(information),
                ],
            );
            p.eax(1);
            // The model enters the child's address space exactly as
            // VirtualAllocEx and WriteProcessMemory already do, finds the image
            // mapped at the requested base and removes it whole.
            p.call(NT_UNMAP, &[M(information), V(image_base)]);
            p.eax(0);
            // The image is gone, so the same request is no longer a mapped view.
            p.call(NT_UNMAP, &[M(information), V(image_base)]);
            p.eax(NOT_MAPPED);
            p.call(TERMINATE, &[M(information), V(1)]);
            p.eax(1);
            // A terminating target has an address space on the way out.
            p.call(NT_UNMAP, &[M(information), V(image_base)]);
            p.eax(TERMINATING);
            p.call(LAST_ERROR, &[]);
            p.eax(0);
        }
    }
    p.finish()
}
