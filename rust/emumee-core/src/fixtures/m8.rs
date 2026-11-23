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
const PAGE_EXECUTE_READWRITE: u64 = 0x40;
const MEM_RELEASE: u64 = 0x8000;
const REGION_BYTES: u64 = 0x1000;

/// The non-PE executable payload the N15 carver must classify as a shellcode
/// region rather than a structural image. Deliberately not `MZ`-headed.
pub fn executable_payload() -> Vec<u8> {
    let mut payload = vec![0x90_u8; 48];
    payload.extend(b"OWNED-SHELLCODE-MARKER");
    payload.push(0xcc);
    payload
}

/// The indicator text this control writes into a live private reservation, so
/// the N14 private-mapping scan has something only that scan can recover.
pub const PRIVATE_INDICATOR: &str = "staged 198.51.100.7 drop http://private.test/stage end";

/// A control that copies an indicator string into a committed private
/// reservation and leaves it live at the settled boundary. The text is staged
/// from the image, so the capture recovers it twice under two different
/// sources — `guest_image_at_stop` and `guest_private_at_stop:<base>` — and the
/// private-source match is what proves the live private-run scan ran.
pub fn private_mapping_probe(architecture: Architecture) -> Vec<u8> {
    let mut probe = Probe::new(
        architecture,
        false,
        &[(
            "kernel32.dll",
            vec![
                "VirtualAlloc".to_string(),
                "GetCurrentProcess".to_string(),
                "WriteProcessMemory".to_string(),
            ],
        )],
    );
    let text = format!("{PRIVATE_INDICATOR}\0");
    let source = probe.blob(text.as_bytes());
    let allocation = probe.scratch(8);
    let process = probe.scratch(8);
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
    probe.call(1, &[]);
    probe.save(process);
    // WriteProcessMemory(handle, reservation, text, len, NULL) — the indicator
    // now lives only in private memory, and the reservation is never freed.
    probe.call(
        2,
        &[
            M(process),
            M(allocation),
            V(source),
            V(text.len() as u64),
            V(0),
        ],
    );
    probe.finish()
}

/// Guest paths the dropped-PE control reads from and writes to.
pub const DROP_SOURCE: &str = r"C:\emumee\staged.bin";
pub const DROP_DESTINATION: &str = r"C:\emumee\dropped.exe";

/// A control that drops a staged PE to a new guest path with `CopyFileA`, the
/// plainest form of a dropper. At the settled boundary the dropped file is
/// retained and its structural image evidence is carved. Returns 1 from its
/// entry.
pub fn dropped_pe_probe(architecture: Architecture) -> Vec<u8> {
    let mut probe = Probe::new(
        architecture,
        false,
        &[("kernel32.dll", vec!["CopyFileA".to_string()])],
    );
    let source = probe.ascii(DROP_SOURCE);
    let destination = probe.ascii(DROP_DESTINATION);
    // CopyFileA(source, destination, FALSE)
    probe.call(0, &[V(source), V(destination), V(0)]);
    probe.finish()
}

/// A control that stages the executable payload into a reservation that is
/// already executable, then releases it. No protection transition occurs, so
/// the only thing that can retain the payload is the release carve — which is
/// the last moment those bytes exist. Returns 1 from its entry.
pub fn released_payload_probe(architecture: Architecture) -> Vec<u8> {
    let mut probe = Probe::new(
        architecture,
        false,
        &[(
            "kernel32.dll",
            vec![
                "VirtualAlloc".to_string(),
                "GetCurrentProcess".to_string(),
                "WriteProcessMemory".to_string(),
                "VirtualFree".to_string(),
            ],
        )],
    );
    let payload = executable_payload();
    let source = probe.blob(&payload);
    let allocation = probe.scratch(8);
    let process = probe.scratch(8);
    // reservation = VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    probe.call(
        0,
        &[
            V(0),
            V(REGION_BYTES),
            V(MEM_COMMIT_RESERVE),
            V(PAGE_EXECUTE_READWRITE),
        ],
    );
    probe.save(allocation);
    probe.call(1, &[]);
    probe.save(process);
    probe.call(
        2,
        &[
            M(process),
            M(allocation),
            V(source),
            V(payload.len() as u64),
            V(0),
        ],
    );
    // VirtualFree(reservation, 0, MEM_RELEASE)
    probe.call(3, &[M(allocation), V(0), V(MEM_RELEASE)]);
    probe.finish()
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
