use super::*;
use emumee_core::{
    fixtures::{self, M4Arg::Value as V, M4Code as Code},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};

const BASE: u32 = 0x400000;
const TABLE: u32 = BASE + 0x3c00;
const COOKIE: u32 = BASE + 0x3d00;
const FRAME: u32 = BASE + 0x3e00;
const CHECKS: u32 = FRAME + 4;
const FILTERS: u32 = FRAME + 8;
const FINALLY: u32 = FRAME + 12;
const GLOBAL: u32 = FRAME + 16;
const SECRET: u32 = 0x5317ace9;

#[derive(Clone, Copy, Default)]
struct Control {
    filter: i32,
    gs: bool,
    local: bool,
    global: bool,
    negative: Option<&'static str>,
}
fn immediate(code: &mut Vec<u8>, prefix: &[u8], value: u32) {
    code.extend_from_slice(prefix);
    code.extend(value.to_le_bytes());
}
fn write(code: &mut Vec<u8>, address: u32, value: u32) {
    immediate(code, &[0xc7, 5], address);
    code.extend(value.to_le_bytes());
}
fn increment(code: &mut Vec<u8>, address: u32) {
    immediate(code, &[0xff, 5], address);
}
fn expect_frame(code: &mut Vec<u8>) {
    immediate(code, &[0x3b, 0x2d], FRAME);
    code.extend([0x74, 1, 0xcc]);
}
fn expect_memory(code: &mut Code, address: u32, value: u32) {
    code.load(address.into());
    code.expect(value);
}
fn finish(code: &mut Vec<u8>) {
    code.extend([
        0x8b, 0x45, 8, 0x64, 0xa3, 0, 0, 0, 0, 0x8d, 0x65, 0x40, 0x5d,
    ]);
    immediate(code, &[0xb8], 1);
    code.push(0xc3);
}
fn run(label: &str, control: Control) -> crate::Execution {
    let arch = Architecture::X86;
    let mut root = Code::new(arch, 0x1000);
    root.bytes
        .extend([0x55, 0x81, 0xec, 0x80, 0, 0, 0, 0x8d, 0x6c, 0x24, 0x40]);
    immediate(&mut root.bytes, &[0x89, 0x2d], FRAME);
    write(&mut root.bytes, COOKIE, SECRET);
    let header = [
        if control.gs { (-32i32) as u32 } else { TOP },
        4,
        (-28i32) as u32,
        0,
    ];
    for (index, value) in header.into_iter().enumerate() {
        write(&mut root.bytes, TABLE + index as u32 * 4, value);
    }
    let entries = if control.local {
        vec![[1, 0, BASE + 0x1b00], [TOP, BASE + 0x1a00, BASE + 0x1c00]]
    } else {
        vec![[TOP, BASE + 0x1a00, BASE + 0x1c00]]
    };
    for (index, entry) in entries.iter().enumerate() {
        for (field, value) in entry.iter().enumerate() {
            write(
                &mut root.bytes,
                TABLE + 16 + index as u32 * 12 + field as u32 * 4,
                *value,
            );
        }
    }
    root.bytes.extend([0x64, 0xa1, 0, 0, 0, 0, 0x89, 0x45, 8]);
    immediate(&mut root.bytes, &[0xc7, 0x45, 12], BASE + 0x1d00);
    root.bytes.extend([0x8d, 0x45, 8, 0x89, 0x45, 0xf0]);
    immediate(&mut root.bytes, &[0xc7, 0x45, 0xf4], BASE + 0x1800);
    immediate(&mut root.bytes, &[0xc7, 0x45, 0xf8], TABLE ^ SECRET);
    immediate(&mut root.bytes, &[0xc7, 0x45, 0xfc], 0);
    root.bytes.extend([0x89, 0x65, 0xe8]);
    immediate(&mut root.bytes, &[0xb8], SECRET);
    root.bytes.extend([0x31, 0xe8, 0x89, 0x45, 0xe4]);
    root.bytes.extend([0x8d, 0x45, 4]);
    immediate(&mut root.bytes, &[0x35], SECRET);
    root.bytes.extend([0x89, 0x45, 0xe0, 0x8d, 0x45, 0xf0]);
    if control.global {
        root.bytes.extend([0x89, 0x45, 0xc8]);
        immediate(&mut root.bytes, &[0xc7, 0x45, 0xcc], BASE + 0x1e00);
        root.bytes.extend([0x8d, 0x45, 0xc8]);
    }
    root.bytes.extend([0x64, 0xa3, 0, 0, 0, 0]);
    match control.negative {
        Some("cycle") => write(&mut root.bytes, TABLE + 16, 0),
        Some("level") => immediate(&mut root.bytes, &[0xc7, 0x45, 0xfc], u32::MAX),
        Some("table") => immediate(&mut root.bytes, &[0xc7, 0x45, 0xf8], 0x12345000 ^ SECRET),
        Some("filter-address") => write(&mut root.bytes, TABLE + 20, 0x12345000),
        Some("handler-address") => write(&mut root.bytes, TABLE + 24, 0x12345000),
        Some("cookie-offset") => write(&mut root.bytes, TABLE + 8, 0x40000000),
        Some("cookie") => root.bytes.extend([0x83, 0x75, 0xe4, 1]),
        Some("gs-cookie") => root.bytes.extend([0x83, 0x75, 0xe0, 1]),
        Some("top") => immediate(&mut root.bytes, &[0xc7, 0x45, 0xfc], TOP),
        Some("noncontinuable") => {
            root.call(0, &[V(0x12345678), V(1), V(0), V(0)]);
        }
        _ => (),
    }
    root.bytes.push(0xcc);
    root.expect(42);
    expect_memory(
        &mut root,
        FILTERS,
        u32::from(control.negative != Some("top")),
    );
    expect_memory(
        &mut root,
        CHECKS,
        if control.negative == Some("top") {
            1
        } else {
            2 * (1 + u32::from(control.gs))
        },
    );
    expect_memory(&mut root, FINALLY, 0);
    finish(&mut root.bytes);

    let mut child = Code::new(arch, 0x1800);
    child.bytes.extend([
        0xff, 0x74, 0x24, 16, 0xff, 0x74, 0x24, 16, 0xff, 0x74, 0x24, 16, 0xff, 0x74, 0x24, 16,
    ]);
    immediate(&mut child.bytes, &[0x68], BASE + 0x1900);
    immediate(&mut child.bytes, &[0x68], COOKIE);
    child.bytes.extend([0xff, 0x15]);
    child.bytes.extend((BASE + 0x2090).to_le_bytes());
    child.bytes.extend([0x83, 0xc4, 24, 0xc3]);
    child.bytes.resize(0x900, 0x90);
    immediate(&mut child.bytes, &[0x3b, 0x0d], COOKIE);
    child.bytes.extend([0x74, 2, 0x0f, 0x0b]);
    increment(&mut child.bytes, CHECKS);
    if control.negative == Some("checker-abi") {
        child.bytes.push(0x43);
    }
    child.bytes.push(0xc3);
    child.bytes.resize(0xa00, 0x90);
    expect_frame(&mut child.bytes);
    increment(&mut child.bytes, FILTERS);
    if control.filter < 0 {
        child
            .bytes
            .extend([0x8b, 0x45, 0xec, 0x8b, 0x40, 4, 0xff, 0x80]);
        child.bytes.extend(184u32.to_le_bytes());
        child.bytes.extend([0xc7, 0x80]);
        child.bytes.extend(176u32.to_le_bytes());
        child.bytes.extend(42u32.to_le_bytes());
    }
    if control.negative == Some("revalidation") {
        child.bytes.extend([0x83, 0x75, 0xe4, 1]);
    }
    if control.negative == Some("filter-abi") {
        child.bytes.extend([0x31, 0xed]);
    }
    immediate(&mut child.bytes, &[0xb8], control.filter as u32);
    child.bytes.push(0xc3);
    child.bytes.resize(0xb00, 0x90);
    expect_frame(&mut child.bytes);
    child.bytes.extend([
        0x83, 0xf9, 1, 0x74, 1, 0xcc, 0x83, 0x7d, 0xfc, 1, 0x74, 1, 0xcc,
    ]);
    increment(&mut child.bytes, FINALLY);
    if control.negative == Some("finally-revalidation") {
        child.bytes.extend([0x83, 0x75, 0xe4, 1]);
    }
    child.bytes.push(0xc3);
    child.bytes.resize(0xc00, 0x90);
    child.bytes.extend([0x8b, 0x65, 0xe8]);
    expect_frame(&mut child.bytes);
    child.bytes.extend([0x83, 0x7d, 0xfc, 0xfe, 0x74, 1, 0xcc]);
    let mut accepting = Code::new(arch, 0x1c00);
    expect_memory(&mut accepting, FILTERS, 1);
    expect_memory(&mut accepting, FINALLY, u32::from(control.local));
    expect_memory(&mut accepting, GLOBAL, u32::from(control.global));
    expect_memory(&mut accepting, CHECKS, 2 * (1 + u32::from(control.gs)));
    finish(&mut accepting.bytes);
    child.bytes.extend(accepting.finish());
    child.bytes.resize(0xd00, 0x90);
    child.bytes.extend([0x8b, 0x44, 0x24, 12, 0xff, 0x80]);
    child.bytes.extend(184u32.to_le_bytes());
    child.bytes.extend([0xc7, 0x80]);
    child.bytes.extend(176u32.to_le_bytes());
    child.bytes.extend(42u32.to_le_bytes());
    child.bytes.extend([0x31, 0xc0, 0xc3]);
    child.bytes.resize(0xe00, 0x90);
    child.bytes.extend([
        0x8b, 0x44, 0x24, 4, 0xf6, 0x40, 4, 2, 0x75, 6, 0xb8, 1, 0, 0, 0, 0xc3,
    ]);
    increment(&mut child.bytes, GLOBAL);
    child.epilogue(
        if control.negative == Some("global-disposition") {
            2
        } else {
            1
        },
        0,
    );

    let mut bytes = fixtures::m4_custom_probe(
        arch,
        &[
            "RaiseException",
            "GetLastError",
            "GetLastError",
            "GetLastError",
            "_except_handler4_common",
        ],
        &root.finish(),
        &child.finish(),
        &[0xc3],
    );
    for raw in [0x1280, 0x1380] {
        bytes[raw + 12..raw + 16].fill(0);
        bytes[raw + 20..raw + 24].fill(0);
    }
    for (offset, value) in [(0x1214, 0x2190u32), (0x1220, 0x2280), (0x1224, 0x2090)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x1228..0x123c].fill(0);
    bytes[0x1480..0x148b].copy_from_slice(b"msvcrt.dll\0");
    bytes[0x98 + 96 + 12..0x98 + 96 + 16].copy_from_slice(&60u32.to_le_bytes());
    let request = Request {
        schema: 2,
        profile: PROFILE.into(),
        run_id: "20261112T120000Z-12345678".into(),
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "eh4-control.exe".into(),
        arguments: vec![],
        max_instructions: 30000,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: vec![],
        invocation: Default::default(),
        capture: None,
        output: None,
    };
    let label = format!("X86-m4-eh4-{label}");
    crate::user_test_fixtures::fixture(&label, &request, &bytes, &[], None);
    let execution = crate::user::run(&request, &bytes, None).unwrap();
    crate::user_test_fixtures::execution(&label, &execution);
    execution
}
fn success(label: &str, control: Control) {
    let result = run(label, control);
    assert_eq!(result.error, None, "{label}: {result:#?}");
    assert_eq!(result.guest_entry_return, Some(1), "{label}: {result:#?}");
    assert!(
        result.api_events.iter().all(|event| !event.pending),
        "{label}: {result:#?}"
    );
    assert_eq!(result.maximum_continuation_depth, 1, "{label}: {result:#?}");
}
#[test]
fn m4_eh4_actual_guest_signed_filters_and_nonreturning_transfer() {
    for (label, filter) in [
        ("continue-negative", -7),
        ("filter-search", 0),
        ("accept-positive", 7),
    ] {
        success(
            label,
            Control {
                filter,
                ..Default::default()
            },
        );
    }
    success(
        "gs-cookie",
        Control {
            filter: 1,
            gs: true,
            ..Default::default()
        },
    );
    success(
        "topmost-search",
        Control {
            negative: Some("top"),
            ..Default::default()
        },
    );
}
#[test]
fn m4_eh4_actual_guest_local_finally_and_global_unwind() {
    for (label, global) in [("local-finally", false), ("global-local-unwind", true)] {
        success(
            label,
            Control {
                filter: 1,
                local: true,
                global,
                ..Default::default()
            },
        );
    }
}
#[test]
fn m4_eh4_actual_guest_malformed_cycle_cookie_and_callback_negatives() {
    for (negative, expected) in [
        ("cycle", "scope cycle"),
        ("level", "malformed scope"),
        ("table", "permission1"),
        ("filter-address", "permission4"),
        ("handler-address", "permission4"),
        ("cookie-offset", "owned stack"),
        ("cookie", "nesting bound"),
        ("gs-cookie", "nesting bound"),
        ("revalidation", "nesting bound"),
        ("finally-revalidation", "nesting bound"),
        ("filter-abi", "nonvolatile"),
        ("checker-abi", "nonvolatile"),
        ("noncontinuable", "noncontinuable"),
        ("global-disposition", "global unwind disposition"),
    ] {
        let result = run(
            &format!("reject-{negative}"),
            Control {
                filter: if negative == "noncontinuable" { -1 } else { 1 },
                gs: negative == "gs-cookie",
                local: negative == "finally-revalidation",
                global: negative == "global-disposition",
                negative: Some(negative),
            },
        );
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|error| error.to_ascii_lowercase().contains(expected)),
            "{negative}: {result:#?}"
        );
        assert_eq!(result.guest_entry_return, None, "{negative}: {result:#?}");
    }
}
