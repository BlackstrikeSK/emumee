//! Generated guest images only; no copied driver code.
use super::*;

pub(super) fn c_fixture(bad_cookie: bool) -> Vec<u8> {
    let mut bytes = fixture(0, 1);
    let put = |data: &mut [u8], at: usize, value: u32| {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes())
    };
    let cookie = 0x123456789abcu64;
    let mut root = vec![0x48, 0x83, 0xec, 0x28, 0x48, 0xb8];
    root.extend((cookie ^ u64::from(bad_cookie)).to_le_bytes());
    root.extend([
        0x48, 0x33, 0xc4, 0x48, 0x89, 0x44, 0x24, 0x20, 0xcc, 0x48, 0x83, 0xc4, 0x28, 0xc3,
    ]);
    bytes[0x200..0x200 + root.len()].copy_from_slice(&root);
    put(&mut bytes, 0x404, 0x1000 + root.len() as u32);
    // Registered generated wrapper checks the real stack cookie before its
    // tail call into the modeled C handler. Failure executes actual UD2.
    let mut wrapper = vec![0x48, 0x8b, 0x42, 0x20, 0x48, 0x33, 0xc2, 0x48, 0x3b, 0x05];
    wrapper.extend((0x20a0i32 - 0x110e).to_le_bytes());
    wrapper.extend([0x75, 6, 0xff, 0x25]);
    wrapper.extend((0x2160i32 - 0x1116).to_le_bytes());
    wrapper.extend([0x0f, 0x0b]);
    bytes[0x300..0x300 + wrapper.len()].copy_from_slice(&wrapper);
    let filter = [
        0x4c, 0x8b, 0x41, 8, 0x49, 0xff, 0x80, 0xf8, 0, 0, 0, 0x49, 0xc7, 0x40, 0x78, 42, 0, 0, 0,
        0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3,
    ];
    bytes[0x380..0x380 + filter.len()].copy_from_slice(&filter);
    // One active filter scope; HandlerData begins immediately after handler RVA.
    for (i, value) in [1, 0x1000, 0x1000 + root.len() as u32, 0x1180, 0x1017]
        .into_iter()
        .enumerate()
    {
        put(&mut bytes, 0x44c + i * 4, value);
    }
    bytes[0x4a0..0x4a8].copy_from_slice(&cookie.to_le_bytes());
    // A single real import; no host DLL is loaded by the emulator.
    put(&mut bytes, 0x98 + 112 + 8, 0x2100);
    put(&mut bytes, 0x98 + 112 + 12, 40);
    for (i, value) in [0x2140, 0, 0, 0x2128, 0x2160].into_iter().enumerate() {
        put(&mut bytes, 0x500 + i * 4, value);
    }
    bytes[0x528..0x535].copy_from_slice(b"ntoskrnl.exe\0");
    bytes[0x540..0x550].fill(0);
    bytes[0x560..0x570].fill(0);
    bytes[0x540..0x548].copy_from_slice(&0x2180u64.to_le_bytes());
    bytes[0x560..0x568].copy_from_slice(&0x2180u64.to_le_bytes());
    bytes[0x580..0x582].fill(0);
    bytes[0x582..0x597].copy_from_slice(b"__C_specific_handler\0");
    bytes
}
#[test]
fn native_exception_c_filter_executes_after_guest_cookie_check_and_resumes_once() {
    let result = run_generated_image(&c_fixture(false), 4000, 30_000_000).unwrap();
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.guest_entry_return, Some(42));
    let report = result.native_exceptions.unwrap();
    assert_eq!(report.c_scope_requests, 1);
    assert_eq!(report.guest_filters, 1);
    let events: Vec<_> = result
        .api_events
        .iter()
        .filter(|event| event.api.ends_with(".__C_specific_handler"))
        .collect();
    assert_eq!(events.len(), 1);
    assert!(!events[0].pending);
    assert_eq!(events[0].result, Some(0));
    let failed = run_generated_image(&c_fixture(true), 4000, 30_000_000).unwrap();
    assert!(failed.error.is_some());
    assert!(failed.guest_entry_return.is_none());
    let report = failed.native_exceptions.unwrap();
    assert_eq!(report.c_scope_requests, 0);
    assert_eq!(report.guest_filters, 0);
}
#[test]
fn native_exception_guest_filter_consumes_full_kernel_context_and_invalid_mxcsr_cannot_resume() {
    let mut bytes = c_fixture(false);
    let original = bytes[0x380..0x399].to_vec();
    let mut filter = vec![0x48, 0x8b, 0x41, 8];
    let mut guards = Vec::new();
    for (offset, value) in [
        (0x30, 0x10001fu32),
        (0x3a, 0x002b002b),
        (0x3e, 0x002b0053),
        (0x34, 0x1f80),
    ] {
        filter.extend([0x81, 0x78, offset]);
        filter.extend(value.to_le_bytes());
        filter.extend([0x75, 0]);
        guards.push(filter.len() - 1);
    }
    filter.extend([0x48, 0x83, 0x78, 0x70, 0, 0x75, 0]);
    guards.push(filter.len() - 1);
    filter.extend([0x81, 0xb8, 0x18, 1, 0, 0]);
    filter.extend(0x1f80u32.to_le_bytes());
    filter.extend([0x75, 0]);
    guards.push(filter.len() - 1);
    filter.extend(original);
    let fail = filter.len();
    filter.extend([0x0f, 0x0b]);
    for at in guards {
        filter[at] = u8::try_from(fail - at - 1).unwrap();
    }
    assert!(filter.len() <= 128);
    bytes[0x380..0x380 + filter.len()].copy_from_slice(&filter);
    let result = run_generated_image(&bytes, 4000, 30_000_000).unwrap();
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.guest_entry_return, Some(42));
    let mut bytes = c_fixture(false);
    // Keep the complete original negative filter, but set an invalid MXCSR
    // in its target context before returning ContinueExecution.
    let original = bytes[0x380..0x399].to_vec();
    let mut filter = vec![0x48, 0x8b, 0x41, 8, 0xc7, 0x40, 0x34, 0, 0, 1, 0];
    filter.extend(original);
    bytes[0x380..0x380 + filter.len()].copy_from_slice(&filter);
    let result = run_generated_image(&bytes, 4000, 30_000_000).unwrap();
    assert!(
        result
            .error
            .as_deref()
            .is_some_and(|e| e.contains("MXCSR has reserved bits")),
        "{result:#?}"
    );
    assert!(result.guest_entry_return.is_none());
}
#[test]
fn native_exception_kernel_handler_uses_prcb_mxcsr_and_restores_the_fault_environment() {
    let mut bytes = c_fixture(false);
    let mut root = vec![
        0x48, 0x83, 0xec, 0x28, 0xc7, 0x44, 0x24, 0x18, 0x80, 0x3f, 0, 0, 0x0f, 0xae, 0x54, 0x24,
        0x18, 0x48, 0xb8,
    ];
    root.extend(0x123456789abcu64.to_le_bytes());
    root.extend([0x48, 0x33, 0xc4, 0x48, 0x89, 0x44, 0x24, 0x20, 0xcc]);
    let continuation = 0x1000 + root.len() as u32;
    root.extend([
        0x0f, 0xae, 0x5c, 0x24, 0x18, 0x81, 0x7c, 0x24, 0x18, 0x80, 0x3f, 0, 0, 0x75, 5, 0x48,
        0x83, 0xc4, 0x28, 0xc3, 0x0f, 0x0b,
    ]);
    bytes[0x200..0x200 + root.len()].copy_from_slice(&root);
    let end = 0x1000 + root.len() as u32;
    for at in [0x404, 0x454] {
        bytes[at..at + 4].copy_from_slice(&end.to_le_bytes());
    }
    bytes[0x45c..0x460].copy_from_slice(&continuation.to_le_bytes());
    let original = bytes[0x380..0x399].to_vec();
    let mut filter = vec![
        0x48, 0x8b, 0x41, 8, 0x81, 0x78, 0x34, 0x80, 0x3f, 0, 0, 0x75, 0,
    ];
    let first = filter.len() - 1;
    filter.extend([
        0x0f, 0xae, 0x5a, 0x18, 0x81, 0x7a, 0x18, 0x80, 0x1f, 0, 0, 0x75, 0,
    ]);
    let second = filter.len() - 1;
    filter.extend(original);
    let fail = filter.len();
    filter.extend([0x0f, 0x0b]);
    for at in [first, second] {
        filter[at] = u8::try_from(fail - at - 1).unwrap();
    }
    bytes[0x380..0x380 + filter.len()].copy_from_slice(&filter);
    let result = run_generated_image(&bytes, 4000, 30_000_000).unwrap();
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.guest_entry_return, Some(42));
}
#[test]
fn native_exception_modeled_breakpoint_api_uses_its_real_caller_for_resume_and_unwind() {
    for positive in [false, true] {
        let mut bytes = c_fixture(false);
        // Add DbgBreakPoint beside the existing C language-handler import.
        bytes[0x548..0x550].copy_from_slice(&0x21b0u64.to_le_bytes());
        bytes[0x550..0x558].fill(0);
        bytes[0x568..0x570].copy_from_slice(&0x21b0u64.to_le_bytes());
        bytes[0x570..0x578].fill(0);
        bytes[0x5b0..0x5b2].fill(0);
        bytes[0x5b2..0x5c0].copy_from_slice(b"DbgBreakPoint\0");
        // The original root cookie prologue is followed by the actual API CALL.
        let mut root = bytes[0x200..0x216].to_vec();
        root.extend([0xff, 0x15]);
        root.extend((0x2168i32 - (0x1000 + root.len() as i32 + 4)).to_le_bytes());
        let continuation = 0x1000 + root.len() as u32;
        root.extend([0x90, 0x48, 0x83, 0xc4, 0x28, 0xc3]);
        bytes[0x200..0x200 + root.len()].copy_from_slice(&root);
        let end = 0x1000 + root.len() as u32;
        for at in [0x404, 0x454] {
            bytes[at..at + 4].copy_from_slice(&end.to_le_bytes());
        }
        bytes[0x45c..0x460].copy_from_slice(&continuation.to_le_bytes());
        if positive {
            bytes[0x458..0x45c].copy_from_slice(&1u32.to_le_bytes());
        }
        let result = run_generated_image(&bytes, 4000, 30_000_000).unwrap();
        assert_eq!(result.error, None, "positive{positive}: {result:#?}");
        assert_eq!(
            result.guest_entry_return,
            Some(if positive { 0x80000003 } else { 42 })
        );
        let report = result.native_exceptions.unwrap();
        assert_eq!(report.api_exceptions.len(), 1);
        assert!(report.api_exceptions[0].delivered);
        assert_eq!(report.events[0].parameters, vec![0]);
        assert_eq!(report.unwinds_completed, u64::from(positive));
        let calls: Vec<_> = result
            .api_events
            .iter()
            .filter(|e| e.api.ends_with(".DbgBreakPoint"))
            .collect();
        assert_eq!(calls.len(), 1);
        assert!(!calls[0].pending);
        assert_eq!(calls[0].result, None);
        assert_eq!(calls[0].effect, Some("raised_native_exception"));
    }
}
#[test]
fn native_exception_leaf_fault_searches_the_actual_callers_registered_handler() {
    let mut bytes = fixture(0, 1);
    let mut root = vec![0x48, 0x83, 0xec, 0x28, 0xe8];
    root.extend((0x11c0i32 - 0x1009).to_le_bytes());
    root.extend([0x90, 0x48, 0x83, 0xc4, 0x28, 0xc3]);
    bytes[0x200..0x200 + root.len()].copy_from_slice(&root);
    bytes[0x404..0x408].copy_from_slice(&(0x1000 + root.len() as u32).to_le_bytes());
    bytes[0x3c0..0x3c2].copy_from_slice(&[0xcc, 0xc3]);
    let result = run_generated_image(&bytes, 2000, 30_000_000).unwrap();
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.guest_entry_return, Some(42));
    let report = result.native_exceptions.unwrap();
    assert_eq!(report.events.len(), 1);
    assert_eq!(
        report.events[0].handler - report.events[0].control_pc,
        0x1100 - 0x1009
    );
    assert_eq!(
        report.events[0].exception_address - report.events[0].control_pc,
        0x11c0 - 0x1009
    );
}
#[test]
fn native_exception_c_filter_zero_unwind_requests_and_budgets_never_fake_a_catch() {
    let mut zero = c_fixture(false);
    zero[0x394..0x398].fill(0);
    let result = run_generated_image(&zero, 4000, 30_000_000).unwrap();
    assert!(
        result
            .error
            .as_deref()
            .is_some_and(|e| e.contains("Unhandled native exception")),
        "{result:#?}"
    );
    assert!(result.guest_entry_return.is_none());
    let event = result
        .api_events
        .iter()
        .find(|e| e.api.ends_with(".__C_specific_handler"))
        .unwrap();
    assert!(!event.pending);
    assert_eq!(event.result, Some(1));
    let mut unwind = c_fixture(false);
    unwind[0x458..0x45c].copy_from_slice(&1u32.to_le_bytes());
    let result = run_generated_image(&unwind, 4000, 30_000_000).unwrap();
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.guest_entry_return, Some(0x80000003));
    assert_eq!(
        result.native_exceptions.as_ref().unwrap().unwinds_completed,
        1
    );
    let mut looping = c_fixture(false);
    looping[0x380..0x382].copy_from_slice(&[0xeb, 0xfe]);
    let result = run_generated_image(&looping, 200, 30_000_000).unwrap();
    assert_eq!(result.error, None);
    assert_eq!(result.completion_reason, "instruction_budget");
    assert_eq!(result.instruction_count, 200);
    assert!(result.guest_entry_return.is_none());
    let event = result
        .api_events
        .iter()
        .find(|e| e.api.ends_with(".__C_specific_handler"))
        .unwrap();
    assert!(event.pending);
    assert_eq!(event.result, None);
    assert_eq!(event.effect, Some("c_language_handler_pending"));
}

fn fixture(kind: u8, version: u8) -> Vec<u8> {
    let mut bytes = counted_driver(Architecture::X64, 1);
    let put = |data: &mut [u8], at: usize, value: u32| {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes())
    };
    // Exception directory: one protected root function, actual handler code.
    put(&mut bytes, 0x98 + 112 + 24, 0x2000);
    put(&mut bytes, 0x98 + 112 + 28, 12);
    for (i, value) in [0x1000, 0x100a, 0x2040].into_iter().enumerate() {
        put(&mut bytes, 0x400 + i * 4, value);
    }
    bytes[0x440..0x448].copy_from_slice(&[8 + version, 4, 1, 0, 4, 0x42, 0, 0]);
    put(&mut bytes, 0x448, if kind == 5 { 0x2080 } else { 0x1100 });
    bytes[0x200..0x20a]
        .copy_from_slice(&[0x48, 0x83, 0xec, 0x28, 0xcc, 0x48, 0x83, 0xc4, 0x28, 0xc3]);
    let mut code = Vec::new();
    match kind {
        1 => code.extend([0xb8, 1, 0, 0, 0, 0xc3]), // continue search
        2 => code.extend([0xb8, 2, 0, 0, 0, 0xc3]), // unsupported nested disposition
        3 => code.extend([0xeb, 0xfe]),             // budget remains shared
        4 => code.extend([0xcc, 0xc3]),             // nested fault is explicitly unsupported
        6 => code.extend([0x48, 0xff, 0xc3, 0x31, 0xc0, 0xc3]), // bad nonvolatile ABI
        _ => {
            // Windows exposes INT3 itself in both fields. The guest handler
            // must advance its saved context explicitly to resume past it.
            code.extend([
                0x49, 0x8b, 0x80, 0xf8, 0, 0, 0, 0x48, 0x2b, 0x41, 0x10, 0x48, 0x83, 0xf8, 0, 0x75,
                0x13,
            ]);
            code.extend([0x49, 0xff, 0x80, 0xf8, 0, 0, 0]);
            // Edit captured RAX; returning disposition0 must apply the edit.
            code.extend([0x49, 0xc7, 0x40, 0x78, 42, 0, 0, 0, 0x31, 0xc0, 0xc3, 0x90]);
            code.extend([0xb8, 1, 0, 0, 0, 0xc3]);
        }
    }
    bytes[0x300..0x300 + code.len()].copy_from_slice(&code);
    bytes
}
#[test]
fn native_exception_guest_handler_edits_fault_context_and_returns_under_v1_v2_metadata() {
    let native: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/native_x64_int3.json")).unwrap();
    assert_eq!(native["schema"], "emumee.native_int3.v1");
    for version in [1, 2] {
        let result = run_generated_image(&fixture(0, version), 2000, 30_000_000).unwrap();
        assert_eq!(result.error, None, "{result:#?}");
        assert_eq!(result.guest_entry_return, Some(42));
        let report = result.native_exceptions.unwrap();
        assert!(!report.active);
        assert!(!report.pending);
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].code, 0x80000003);
        assert_eq!(report.exceptions_raised, 1);
        assert_eq!(
            report.events[0].code as u64,
            native["code"].as_u64().unwrap()
        );
        assert_eq!(
            report.events[0].parameters.len() as u64,
            native["parameters"].as_u64().unwrap()
        );
        assert_eq!(
            report.events[0].parameters[0],
            native["first_parameter"].as_u64().unwrap()
        );
        assert_eq!(
            report.events[0].control_pc - report.events[0].exception_address,
            native["context_pc_minus_exception_address"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(report.events[0].disposition, Some(0));
        assert_eq!(
            report.events[0].control_pc,
            report.events[0].exception_address
        );
    }
}
#[test]
fn native_exception_handler_failures_and_budget_do_not_become_success() {
    for (kind, expected) in [
        (1, "Unhandled native exception"),
        (2, "Unsupported exception-handler disposition"),
        (4, "Nested native exception dispatch"),
        (5, "lacks permission"),
        (6, "nonvolatile"),
    ] {
        let result = run_generated_image(&fixture(kind, 1), 2000, 30_000_000).unwrap();
        assert!(result.guest_entry_return.is_none(), "{result:#?}");
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains(expected)),
            "kind {kind}: {result:#?}"
        );
    }
    let result = run_generated_image(&fixture(3, 1), 200, 30_000_000).unwrap();
    assert!(result.guest_entry_return.is_none());
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.instruction_count, 200);
    let report = result.native_exceptions.unwrap();
    assert!(report.active);
    assert_eq!(report.events[0].disposition, None);
}

fn msr_fixture(write: bool, kind: u8) -> Vec<u8> {
    let mut bytes = fixture(kind, 1);
    let mut root = vec![0x48, 0x83, 0xec, 0x28, 0xb9];
    root.extend(0x4b564d00u32.to_le_bytes());
    root.push(0xb8);
    root.extend(0x11223344u32.to_le_bytes());
    root.push(0xba);
    root.extend(0x55667788u32.to_le_bytes());
    root.extend([
        0x0f,
        if write { 0x30 } else { 0x32 },
        0x48,
        0x83,
        0xc4,
        0x28,
        0xc3,
    ]);
    bytes[0x200..0x200 + root.len()].copy_from_slice(&root);
    bytes[0x404..0x408].copy_from_slice(&(0x1000 + root.len() as u32).to_le_bytes());
    if kind == 0 {
        let mut handler = Vec::new();
        let mut guards = Vec::new();
        // Verify the fault record and the saved pre-instruction GPRs in guest
        // code, before requesting continuation past the two-byte instruction.
        handler.extend([0x81, 0x39]);
        handler.extend(0xc0000096u32.to_le_bytes());
        handler.extend([0x75, 0]);
        guards.push(handler.len() - 1);
        handler.extend([0x83, 0x79, 0x18, 0, 0x75, 0]);
        guards.push(handler.len() - 1);
        for (offset, value) in [
            (0x78u32, 0x11223344u32),
            (0x80, 0x4b564d00),
            (0x88, 0x55667788),
        ] {
            handler.extend([0x49, 0x81, 0xb8]);
            handler.extend(offset.to_le_bytes());
            handler.extend(value.to_le_bytes());
            handler.extend([0x75, 0]);
            guards.push(handler.len() - 1);
        }
        handler.extend([0x41, 0xf7, 0x40, 0x44]);
        handler.extend(0x10000u32.to_le_bytes());
        handler.extend([0x74, 0]);
        guards.push(handler.len() - 1);
        handler.extend([
            0x49, 0x8b, 0x80, 0xf8, 0, 0, 0, 0x48, 0x2b, 0x41, 0x10, 0x75, 0,
        ]);
        guards.push(handler.len() - 1);
        handler.extend([0x49, 0x83, 0x80, 0xf8, 0, 0, 0, 2]);
        handler.extend([0x49, 0xc7, 0x40, 0x78, 42, 0, 0, 0, 0x31, 0xc0, 0xc3]);
        let failure = handler.len();
        handler.extend([0x0f, 0x0b]);
        for at in guards {
            handler[at] = u8::try_from(failure - at - 1).unwrap();
        }
        assert!(handler.len() <= 256);
        bytes[0x300..0x300 + handler.len()].copy_from_slice(&handler);
    }
    bytes
}

#[test]
fn native_msr_gp_registered_handler_sees_windows_fault_context_before_read_or_write() {
    let native: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/native_x64_msr_gp.json"
    ))
    .unwrap();
    assert_eq!(native["schema"], "emumee.native_msr_gp.v1");
    assert_eq!(native["user_mode_only"], true);
    assert_eq!(native["cpl0_msr_availability_proven"], false);
    for write in [false, true] {
        let result = run_generated_image(&msr_fixture(write, 0), 2000, 30_000_000).unwrap();
        assert_eq!(result.error, None, "{result:#?}");
        assert_eq!(result.guest_entry_return, Some(42));
        let report = result.native_exceptions.unwrap();
        assert_eq!(report.exceptions_raised, 1);
        assert_eq!(report.cpu_faults.len(), 1);
        let fault = &report.cpu_faults[0];
        assert_eq!(
            (fault.vector, fault.error_code, fault.instruction_size),
            (13, 0, 2)
        );
        assert_eq!(fault.msr_index, 0x4b564d00);
        assert_eq!(fault.write, write);
        assert!(fault.saved_resume_flag);
        let event = &report.events[0];
        assert_eq!(u64::from(event.code), native["code"].as_u64().unwrap());
        assert_eq!(
            event.parameters.len() as u64,
            native["parameters"].as_u64().unwrap()
        );
        assert_eq!(
            event.control_pc - event.exception_address,
            native["context_minus_record_pc"].as_u64().unwrap()
        );
        assert_eq!(event.exception_address, fault.pc);
        assert_eq!(event.disposition, Some(0));
        assert!(result.native_cpu_reads.is_none());
    }
}

#[test]
fn native_msr_gp_unhandled_nested_and_budget_do_not_turn_into_zero_or_return() {
    let unhandled = run_generated_image(&msr_fixture(false, 1), 2000, 30_000_000).unwrap();
    assert!(
        unhandled
            .error
            .as_deref()
            .is_some_and(|e| e.contains("Unhandled native exception")),
        "{unhandled:#?}"
    );
    assert_eq!(unhandled.guest_entry_return, None);
    let mut nested = msr_fixture(false, 1);
    nested[0x300..0x308].copy_from_slice(&[0xb9, 0, 0x4d, 0x56, 0x4b, 0x0f, 0x32, 0xc3]);
    let nested = run_generated_image(&nested, 2000, 30_000_000).unwrap();
    assert!(
        nested
            .error
            .as_deref()
            .is_some_and(|e| e.contains("Nested native fault")),
        "{nested:#?}"
    );
    assert_eq!(nested.guest_entry_return, None);
    let complete = run_generated_image(&msr_fixture(false, 0), 2000, 30_000_000).unwrap();
    let ordinal = complete.native_exceptions.as_ref().unwrap().cpu_faults[0].instruction_count;
    for budget in [
        ordinal - 1,
        ordinal,
        ordinal + 2,
        complete.instruction_count - 1,
    ] {
        let partial = run_generated_image(&msr_fixture(false, 0), budget, 30_000_000).unwrap();
        assert_eq!(partial.error, None, "budget {budget}: {partial:#?}");
        assert_eq!(partial.completion_reason, "instruction_budget");
        assert_eq!(partial.instruction_count, budget);
        assert_eq!(partial.guest_entry_return, None);
    }
}

#[test]
fn native_msr_gp_c_scope_guest_cookie_and_target_unwind_execute() {
    let mut bytes = c_fixture(false);
    let mut root = bytes[0x200..0x216].to_vec();
    root.push(0xb9);
    root.extend(0x4b564d00u32.to_le_bytes());
    root.extend([0x0f, 0x32]);
    let continuation = 0x1000 + root.len() as u32;
    root.extend([0x90, 0x48, 0x83, 0xc4, 0x28, 0xc3]);
    bytes[0x200..0x200 + root.len()].copy_from_slice(&root);
    let end = 0x1000 + root.len() as u32;
    for (offset, value) in [
        (0x404, end),
        (0x454, end),
        (0x458, 1),
        (0x45c, continuation),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    let result = run_generated_image(&bytes, 4000, 30_000_000).unwrap();
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.guest_entry_return, Some(0xc0000096));
    let report = result.native_exceptions.unwrap();
    assert_eq!(report.cpu_faults.len(), 1);
    assert_eq!(report.unwinds_started, 1);
    assert_eq!(report.unwinds_completed, 1);
}
