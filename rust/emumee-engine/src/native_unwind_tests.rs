//! Closed programs exercising guest filter -> unwind/finally -> catch.
use super::*;
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn relative(code: &mut Vec<u8>, base: u32, prefix: &[u8], target: u32, suffix: &[u8]) {
    code.extend(prefix);
    let next = base + code.len() as u32 + 4 + suffix.len() as u32;
    code.extend((target as i32 - next as i32).to_le_bytes());
    code.extend(suffix);
}
fn check(code: &mut Vec<u8>, patches: &mut Vec<usize>) {
    code.extend([0x75, 0]);
    patches.push(code.len() - 1);
}
fn finish(code: &mut Vec<u8>, patches: &[usize]) {
    let fail = code.len();
    code.extend([0x0f, 0x0b]);
    for at in patches {
        code[*at] = u8::try_from(fail - at - 1).unwrap();
    }
}
fn cookie(code: &mut Vec<u8>, bad: bool) {
    code.extend([0x48, 0xb8]);
    code.extend((0x123456789abcu64 ^ u64::from(bad)).to_le_bytes());
    code.extend([0x48, 0x33, 0xc4, 0x48, 0x89, 0x44, 0x24, 0x28]);
}
fn fixture(version: u8, bad_inner_cookie: bool) -> Vec<u8> {
    let mut bytes = super::native_exception_tests::c_fixture(false);
    bytes[0x200..0x400].fill(0x90);
    bytes[0x400..0x4a0].fill(0);
    let mut root = vec![0x53, 0x48, 0x83, 0xec, 0x30, 0xbb, 41, 0, 0, 0];
    cookie(&mut root, false);
    relative(&mut root, 0x1000, &[0xe8], 0x1080, &[]);
    root.extend([0x90, 0x0f, 0x0b]);
    bytes[0x200..0x200 + root.len()].copy_from_slice(&root);
    let mut catch = vec![0x3d, 3, 0, 0, 0x80];
    let mut guards = Vec::new();
    check(&mut catch, &mut guards);
    catch.extend([0x48, 0x83, 0xfb, 41]);
    check(&mut catch, &mut guards);
    relative(&mut catch, 0x1040, &[0x83, 0x3d], 0x20b0, &[2]);
    check(&mut catch, &mut guards);
    catch.extend([0x48, 0x8b, 0x44, 0x24, 0x28, 0x48, 0x33, 0xc4]);
    relative(&mut catch, 0x1040, &[0x48, 0x3b, 0x05], 0x20a0, &[]);
    check(&mut catch, &mut guards);
    relative(
        &mut catch,
        0x1040,
        &[0xc7, 0x05],
        0x20b0,
        &3u32.to_le_bytes(),
    );
    catch.extend([0xb8, 42, 0, 0, 0, 0x48, 0x83, 0xc4, 0x30, 0x5b, 0xc3]);
    finish(&mut catch, &guards);
    assert!(catch.len() <= 64);
    bytes[0x240..0x240 + catch.len()].copy_from_slice(&catch);
    let mut inner = vec![0x53, 0x48, 0x83, 0xec, 0x30, 0xbb, 99, 0, 0, 0];
    cookie(&mut inner, bad_inner_cookie);
    inner.extend([0xcc, 0x90, 0x48, 0x83, 0xc4, 0x30, 0x5b, 0xc3]);
    bytes[0x280..0x280 + inner.len()].copy_from_slice(&inner);
    // A non-tail wrapper with its own allocation and unwind metadata. Its live
    // guest frame must unwind before crossing the owned dispatcher boundary.
    let mut wrapper = vec![
        0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x42, 0x28, 0x48, 0x33, 0xc2,
    ];
    relative(&mut wrapper, 0x1100, &[0x48, 0x3b, 0x05], 0x20a0, &[]);
    let mut guards = Vec::new();
    check(&mut wrapper, &mut guards);
    relative(&mut wrapper, 0x1100, &[0xff, 0x15], 0x2160, &[]);
    wrapper.extend([0x90, 0x48, 0x83, 0xc4, 0x28, 0xc3]);
    finish(&mut wrapper, &guards);
    bytes[0x300..0x300 + wrapper.len()].copy_from_slice(&wrapper);
    let mut filter = Vec::new();
    let mut guards = Vec::new();
    relative(&mut filter, 0x1140, &[0x83, 0x3d], 0x20b0, &[0]);
    check(&mut filter, &mut guards);
    relative(
        &mut filter,
        0x1140,
        &[0xc7, 0x05],
        0x20b0,
        &1u32.to_le_bytes(),
    );
    filter.extend([0xb8, 1, 0, 0, 0, 0xc3]);
    finish(&mut filter, &guards);
    bytes[0x340..0x340 + filter.len()].copy_from_slice(&filter);
    let mut finally = vec![0x83, 0xf9, 1];
    let mut guards = Vec::new();
    check(&mut finally, &mut guards);
    relative(&mut finally, 0x1180, &[0x83, 0x3d], 0x20b0, &[1]);
    check(&mut finally, &mut guards);
    relative(
        &mut finally,
        0x1180,
        &[0xc7, 0x05],
        0x20b0,
        &2u32.to_le_bytes(),
    );
    finally.push(0xc3);
    finish(&mut finally, &guards);
    bytes[0x380..0x380 + finally.len()].copy_from_slice(&finally);
    for (i, row) in [
        [0x1000, 0x1080, 0x2040],
        [0x1080, 0x10b0, 0x2060],
        [0x1100, 0x1130, 0x2080],
    ]
    .into_iter()
    .enumerate()
    {
        for (j, value) in row.into_iter().enumerate() {
            put(&mut bytes, 0x400 + i * 12 + j * 4, value);
        }
    }
    put(&mut bytes, 0x98 + 112 + 28, 36);
    for (offset, flags) in [(0x440, 24), (0x460, 16)] {
        bytes[offset..offset + 8].copy_from_slice(&[flags + version, 5, 2, 0, 5, 0x52, 1, 0x30]);
        put(&mut bytes, offset + 8, 0x1100);
    }
    for (i, value) in [1, 0x1005, 0x1040, 0x1140, 0x1040].into_iter().enumerate() {
        put(&mut bytes, 0x44c + i * 4, value);
    }
    for (i, value) in [1, 0x1085, 0x10b0, 0x1180, 0].into_iter().enumerate() {
        put(&mut bytes, 0x46c + i * 4, value);
    }
    bytes[0x480..0x488].copy_from_slice(&[version, 4, 1, 0, 4, 0x42, 0, 0]);
    bytes[0x4b0..0x4b4].fill(0);
    bytes
}
#[test]
fn native_exception_unwind_executes_guest_finally_then_restores_catch_frame_and_nonvolatiles() {
    let native: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/native_x64_catch_finally.json"
    ))
    .unwrap();
    assert_eq!(native["order"], serde_json::json!([1, 2, 3]));
    assert_eq!(native["abnormal_termination"], 1);
    assert_eq!(native["same_target_frame"], true);
    for version in [1, 2] {
        let result = run_generated_image(&fixture(version, false), 4000, 30_000_000).unwrap();
        assert_eq!(result.error, None, "version{version}: {result:#?}");
        assert_eq!(result.guest_entry_return, native["result"].as_u64());
        let report = result.native_exceptions.unwrap();
        assert_eq!(report.events.len(), 3);
        assert_eq!(report.events[0].phase, "search");
        assert_eq!(
            report.events[0].code as u64,
            native["filter_code"].as_u64().unwrap()
        );
        assert_eq!(report.events[1].phase, "unwind");
        assert_eq!(report.events[1].flags, 2);
        assert_eq!(report.events[2].phase, "unwind");
        assert_eq!(report.events[2].flags, 0x22);
        assert_eq!(report.events[1].disposition, Some(1));
        assert_eq!(report.events[2].disposition, Some(1));
        assert_eq!(report.guest_filters, 1);
        assert_eq!(report.guest_finally, 1);
        assert_eq!(report.unwinds_started, 1);
        assert_eq!(report.unwinds_completed, 1);
        assert_eq!(report.transient_unwind_frames, 1);
        assert_eq!(report.dispatcher_boundaries_crossed, 1);
        let events: Vec<_> = result
            .api_events
            .iter()
            .filter(|e| e.api.ends_with(".__C_specific_handler"))
            .collect();
        assert_eq!(events.len(), 3);
        assert!(!events[0].pending);
        assert_eq!(events[0].result, None);
        assert_eq!(events[0].effect, Some("unwinds_to_c_handler"));
        assert!(
            events[1..]
                .iter()
                .all(|e| !e.pending && e.result == Some(1))
        );
    }
}
#[test]
fn native_exception_unwind_cookie_failures_and_finally_budgets_never_finish_a_catch() {
    let result = run_generated_image(&fixture(1, true), 4000, 30_000_000).unwrap();
    assert!(result.error.is_some());
    assert!(result.guest_entry_return.is_none());
    let report = result.native_exceptions.unwrap();
    assert_eq!(report.unwinds_started, 1);
    assert_eq!(report.unwinds_completed, 0);
    assert_eq!(report.guest_finally, 0);
    let mut bytes = fixture(1, false);
    bytes[0x380..0x382].copy_from_slice(&[0xeb, 0xfe]);
    let result = run_generated_image(&bytes, 200, 30_000_000).unwrap();
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.completion_reason, "instruction_budget");
    assert_eq!(result.instruction_count, 200);
    assert!(result.guest_entry_return.is_none());
    let report = result.native_exceptions.unwrap();
    assert_eq!(report.unwinds_started, 1);
    assert_eq!(report.unwinds_completed, 0);
    assert_eq!(report.guest_finally, 1);
}
#[test]
fn native_exception_handler_inside_dpc_keeps_the_real_dpc_return_boundary() {
    use emumee_core::fixtures::{DpcFixture, kernel_dpc_probe};
    let mut bytes = kernel_dpc_probe(Architecture::X64, DpcFixture::Basic);
    let before = run_generated_image(&bytes, 20000, 30_000_000).unwrap();
    assert_eq!(before.error, None);
    let old = (0x140000000u64 + 0x1900).to_le_bytes();
    let new = (0x140000000u64 + 0x1e00).to_le_bytes();
    let mut patches = 0;
    for at in 0x200..0xb00 - 7 {
        if bytes[at..at + 8] == old {
            bytes[at..at + 8].copy_from_slice(&new);
            patches += 1;
        }
    }
    assert!(patches > 0);
    // A protected leaf trampoline preserves the DPC's four arguments, handles
    // its own trap, then executes the complete original generated callback.
    bytes[0x1000..0x1006].copy_from_slice(&[0xcc, 0xe9, 0, 0, 0, 0]);
    bytes[0x1002..0x1006].copy_from_slice(&(0x1900i32 - 0x1e06).to_le_bytes());
    bytes[0x1100..0x110a].copy_from_slice(&[0x49, 0xff, 0x80, 0xf8, 0, 0, 0, 0x31, 0xc0, 0xc3]);
    put(&mut bytes, 0x98 + 112 + 24, 0x4e00);
    put(&mut bytes, 0x98 + 112 + 28, 12);
    for (i, value) in [0x1e00, 0x1e06, 0x4e20].into_iter().enumerate() {
        put(&mut bytes, 0x4000 + i * 4, value);
    }
    bytes[0x4020..0x4024].copy_from_slice(&[9, 0, 0, 0]);
    put(&mut bytes, 0x4024, 0x1f00);
    let result = run_generated_image(&bytes, 20000, 30_000_000).unwrap();
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.guest_entry_return, before.guest_entry_return);
    let report = result.native_exceptions.unwrap();
    assert_eq!(report.exceptions_raised, 1);
    assert_eq!(report.events[0].disposition, Some(0));
    let dpc = &result.kernel_threads.unwrap().dpc;
    assert_eq!(dpc.counters.restored, 1);
    assert!(!dpc.active);
    assert!(!dpc.native_effect_failure);
}
#[test]
fn native_exception_dispatch_uses_live_guest_exception_flags_and_filter_code() {
    let mut bytes = super::native_exception_tests::c_fixture(false);
    bytes[0x380..0x38f].copy_from_slice(&[
        0x48, 0x8b, 0x01, 0xc7, 0, 0x78, 0x56, 0x34, 0x12, 0xb8, 1, 0, 0, 0, 0xc3,
    ]);
    let result = run_generated_image(&bytes, 4000, 30_000_000).unwrap();
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.guest_entry_return, Some(0x12345678));
    assert_eq!(result.native_exceptions.unwrap().unwinds_completed, 1);
    // A negative filter returns ContinueExecution; guest mutations making the
    // same record noncontinuable must be honored by the outer dispatcher.
    let mut bytes = super::native_exception_tests::c_fixture(false);
    bytes[0x380..0x392].copy_from_slice(&[
        0x48, 0x8b, 0x01, 0xc7, 0x40, 4, 1, 0, 0, 0, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3, 0x90, 0x90,
    ]);
    let result = run_generated_image(&bytes, 4000, 30_000_000).unwrap();
    assert!(
        result
            .error
            .as_deref()
            .is_some_and(|e| e.contains("noncontinuable exception")),
        "{result:#?}"
    );
    assert!(result.guest_entry_return.is_none());
}
#[test]
fn native_exception_unwinds_active_guest_wrapper_handlers_before_original_finally() {
    let mut bytes = fixture(1, false);
    // Give the actively executing language wrapper a real UHANDLER. Its
    // side effect must precede the finally in the original faulting function.
    bytes[0x480] = 17;
    put(&mut bytes, 0x488, 0x11c0);
    let mut handler = vec![0x83, 0x79, 4, 2];
    let mut guards = Vec::new();
    check(&mut handler, &mut guards);
    relative(&mut handler, 0x11c0, &[0xff, 0x05], 0x20b4, &[]);
    handler.extend([0xb8, 1, 0, 0, 0, 0xc3]);
    finish(&mut handler, &guards);
    bytes[0x3c0..0x3c0 + handler.len()].copy_from_slice(&handler);
    let mut finally = vec![0x83, 0xf9, 1];
    let mut guards = Vec::new();
    check(&mut finally, &mut guards);
    relative(&mut finally, 0x1180, &[0x83, 0x3d], 0x20b4, &[1]);
    check(&mut finally, &mut guards);
    relative(&mut finally, 0x1180, &[0x83, 0x3d], 0x20b0, &[1]);
    check(&mut finally, &mut guards);
    relative(
        &mut finally,
        0x1180,
        &[0xc7, 0x05],
        0x20b0,
        &2u32.to_le_bytes(),
    );
    finally.push(0xc3);
    finish(&mut finally, &guards);
    bytes[0x380..0x380 + finally.len()].copy_from_slice(&finally);
    let result = run_generated_image(&bytes, 4000, 30_000_000).unwrap();
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.guest_entry_return, Some(42));
    let report = result.native_exceptions.unwrap();
    assert_eq!(report.events.len(), 4);
    assert_eq!(report.events[1].handler - report.events[0].handler, 0xc0);
    assert_eq!(report.events[1].flags, 2);
    assert_eq!(report.events[1].disposition, Some(1));
    assert_eq!(report.guest_finally, 1);
    assert_eq!(report.unwinds_completed, 1);
}
