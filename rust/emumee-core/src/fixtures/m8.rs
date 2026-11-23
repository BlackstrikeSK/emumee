//! M8 guest controls for the submitted-sample capture obligations (N14/N15).
//!
//! The memory-string controls embed indicator strings in their own image data;
//! the submitted-sample scanner recovers them from the settled image when the
//! request configures capture. Each control decides nothing itself beyond
//! returning 1 — the capture configuration, not the guest, drives the feature.
use super::m6::Probe;
use super::winhttp::Arg::{Memory as M, Value as V};
use crate::pe::Architecture;

/// Win32 constants the executable-region control drives.
const MEM_COMMIT_RESERVE: u64 = 0x3000;
const PAGE_READWRITE: u64 = 4;
const PAGE_EXECUTE_READ: u64 = 0x20;
const REGION_BYTES: u64 = 0x1000;

/// The non-PE executable payload the N15 carver must classify as a shellcode
/// region rather than a structural image. Deliberately not `MZ`-headed.
pub fn executable_payload() -> Vec<u8> {
    let mut payload = vec![0x90_u8; 48];
    payload.extend(b"OWNED-SHELLCODE-MARKER");
    payload.push(0xcc);
    payload
}

/// A control that stages a non-PE executable payload into a guest reservation
/// and transitions it to executable protection, which is the moment the N15
/// carver retains it. Returns 1 from its entry.
pub fn executable_region_probe(architecture: Architecture) -> Vec<u8> {
    // Every export here is stdcall, so the generated caller needs no cdecl
    // stack cleanup: the modeled callee retires its own arguments.
    let mut probe = Probe::new(
        architecture,
        false,
        &[(
            "kernel32.dll",
            vec![
                "VirtualAlloc".to_string(),
                "VirtualProtect".to_string(),
                "GetCurrentProcess".to_string(),
                "WriteProcessMemory".to_string(),
            ],
        )],
    );
    let payload = executable_payload();
    let source = probe.blob(&payload);
    let allocation = probe.scratch(8);
    let process = probe.scratch(8);
    let previous = probe.scratch(8);
    // reservation = VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    probe.call(
        0,
        &[
            V(0),
            V(REGION_BYTES),
            V(MEM_COMMIT_RESERVE),
            V(PAGE_READWRITE),
        ],
    );
    probe.save(allocation);
    // handle = GetCurrentProcess()
    probe.call(2, &[]);
    probe.save(process);
    // WriteProcessMemory(handle, reservation, payload, len, NULL)
    probe.call(
        3,
        &[
            M(process),
            M(allocation),
            V(source),
            V(payload.len() as u64),
            V(0),
        ],
    );
    // VirtualProtect(reservation, 0x1000, PAGE_EXECUTE_READ, &previous)
    probe.call(
        1,
        &[
            M(allocation),
            V(REGION_BYTES),
            V(PAGE_EXECUTE_READ),
            V(previous),
        ],
    );
    probe.finish()
}

/// A control whose settled image carries indicator strings for the N14 scanner:
/// a built-in IPv4 and URL always, plus a lowercase-hex digest a custom pattern
/// recovers when `custom` is set. Returns 1 from its entry.
pub fn memory_string_probe(architecture: Architecture, custom: bool) -> Vec<u8> {
    let mut probe = Probe::new(
        architecture,
        false,
        &[("kernel32.dll", vec!["GetLastError".to_string()])],
    );
    // One printable run carrying both built-in indicators; the scanner extracts
    // the IPv4 and the URL from inside it.
    probe.ascii("c2 203.0.113.1 beacon http://indicator.test/payload end");
    if custom {
        probe.ascii("digest d41d8cd98f00b204e9800998ecf8427e marker");
    }
    probe.finish()
}
