use super::*;
use emumee_core::fixtures::{ApiFixture, api_probe};

#[test]
fn prompt_x64_response_is_opaque_and_capacity_is_the_native_low_word() {
    for capacity in [0u32, 0x10020, u32::MAX] {
        let mut image = api_probe(Architecture::X64, ApiFixture::Prompt);
        image[0x20b..0x212].copy_from_slice(&[0x31, 0xd2, 0x90, 0x90, 0x90, 0x90, 0x90]);
        image[0x214..0x218].copy_from_slice(&capacity.to_le_bytes());
        let e = run_generated_image(&image, 10000, 30_000_000).unwrap();
        assert_eq!(e.error, None, "{e:#?}");
        assert_eq!(e.guest_entry_return, Some(0x52525252));
        let row = &e.kernel_prompt.as_ref().unwrap().observations[0];
        assert_eq!(row.response_address, 0);
        assert_eq!(row.length, capacity);
        assert_eq!(row.effective_response_capacity, capacity as u16);
        assert_eq!(row.result, None);
    }
}

#[test]
fn prompt_x64_unhandled_exception_cannot_become_a_normal_zero_return() {
    let mut image = api_probe(Architecture::X64, ApiFixture::Prompt);
    image[0x1e58..0x1e5c].copy_from_slice(&0x1b00u32.to_le_bytes());
    image[0xd00..0xd03].copy_from_slice(&[0x31, 0xc0, 0xc3]); // Real filter returns search0.
    let e = run_generated_image(&image, 10000, 30_000_000).unwrap();
    assert!(
        e.error
            .as_deref()
            .is_some_and(|e| e.contains("Unhandled native exception")),
        "{e:#?}"
    );
    assert_eq!(e.guest_entry_return, None);
    assert_eq!(e.api_events[0].result, None);
    assert_eq!(e.native_exceptions.unwrap().unwinds_completed, 0);
}

#[test]
fn prompt_x64_no_debugger_runs_registered_catch_without_a_normal_api_return() {
    for kind in [ApiFixture::Prompt, ApiFixture::PromptReadOnly] {
        let e =
            run_generated_image(&api_probe(Architecture::X64, kind), 10000, 30_000_000).unwrap();
        assert_eq!(e.error, None, "{e:#?}");
        assert_eq!(e.guest_entry_return, Some(0x52525252));
        let prompt = e.kernel_prompt.as_ref().unwrap();
        assert_eq!(prompt.input_policy, "no_debugger_exception");
        assert_eq!(prompt.calls, 1);
        assert_eq!(prompt.observations[0].result, None);
        assert_eq!(prompt.observations[0].exception_code, Some(0x80000003));
        assert_eq!(prompt.observations[0].effective_response_capacity, 32);
        assert_eq!(prompt.response_writes, 0);
        let native = e.native_exceptions.as_ref().unwrap();
        assert_eq!(native.api_exceptions.len(), 1);
        assert!(native.api_exceptions[0].delivered);
        assert_eq!(native.events[0].parameters, vec![2]);
        assert_eq!(
            native.events[0].exception_address,
            native.api_exceptions[0].fault_site + 1
        );
        assert_eq!(native.unwinds_completed, 1);
        assert_eq!(e.api_calls, 3);
        assert_eq!(e.api_events[0].result, None);
        assert_eq!(e.api_events[0].effect, Some("raised_native_exception"));
        let window = prompt.continuation.as_ref().unwrap();
        assert!(!window.active);
        assert!(!window.truncated);
        let stop = window.stop.as_ref().unwrap();
        assert_eq!(stop.reason, "next_api_gate");
        assert_eq!(stop.pc, Some(e.api_events[1].api_gate_pc));
        assert_eq!(window.instructions.len(), 1); // Actual guest C-handler wrapper JMP.
        assert_eq!(
            window.instructions[0].instruction_ordinal,
            window.first_prompt_ordinal
        );
        assert_eq!(window.instructions[0].pc, e.image_load.base + 0x1a00);
    }
}

#[test]
fn prompt_x64_negative_filter_checks_trap_context_and_preserves_helper_rax_on_resume() {
    let mut image = api_probe(Architecture::X64, ApiFixture::PromptReadOnly);
    let catch = u32::from_le_bytes(image[0x1e5c..0x1e60].try_into().unwrap());
    // Replace the unconditional filter with real guest code. Normal continuation
    // is possible only after this filter advances the saved INT3 context.
    image[0x1e58..0x1e5c].copy_from_slice(&0x1b00u32.to_le_bytes());
    let at = (catch - 0x1000) as usize + 0x200;
    image[at - 2..at].fill(0x90); // Remove deliberate normal-return UD2 for this case.
    image[at + 1..at + 5].copy_from_slice(&2u32.to_le_bytes()); // Helper result stays2.
    let mut filter = vec![0x4c, 0x8b, 1, 0x4c, 0x8b, 0x49, 8];
    let mut branches = Vec::new();
    for check in [
        vec![0x41, 0x81, 0x38, 3, 0, 0, 0x80],
        vec![0x41, 0x83, 0x78, 0x18, 1],
        vec![0x49, 0x83, 0x78, 0x20, 2],
        vec![0x49, 0x83, 0x79, 0x78, 2],
    ] {
        filter.extend(check);
        filter.extend([0x75, 0]);
        branches.push(filter.len() - 1);
    }
    filter.extend([
        0x49, 0x8b, 0x40, 0x10, 0x49, 0x2b, 0x81, 0xf8, 0, 0, 0, 0x48, 0x83, 0xf8, 1, 0x75, 0,
    ]);
    branches.push(filter.len() - 1);
    filter.extend([
        0x49, 0xff, 0x81, 0xf8, 0, 0, 0, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3,
    ]);
    let fail = filter.len();
    filter.extend([0x0f, 0x0b]);
    for at in branches {
        filter[at] = u8::try_from(fail - at - 1).unwrap();
    }
    image[0xd00..0xd00 + filter.len()].copy_from_slice(&filter);
    let e = run_generated_image(&image, 10000, 30_000_000).unwrap();
    assert_eq!(e.error, None, "{e:#?}");
    assert_eq!(e.guest_entry_return, Some(0x52525252));
    let native = e.native_exceptions.unwrap();
    assert_eq!(native.guest_filters, 1);
    assert_eq!(native.unwinds_completed, 0);
    assert_eq!(native.exceptions_raised, 1);
    assert_eq!(e.api_events[0].result, None);
}

fn fixture(architecture: Architecture, repeat: bool, long: bool) -> Vec<u8> {
    let mut image = api_probe(architecture, ApiFixture::Prompt);
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000u64 };
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x48]);
    }
    fn prompt(code: &mut Vec<u8>, wide: bool, base: u64) {
        if wide {
            for (register, value) in [
                ([0x48, 0xb9], base + 0x2b00),
                ([0x48, 0xba], base + 0x2b40),
                ([0x49, 0xb8], 32),
            ] {
                code.extend(register);
                code.extend(value.to_le_bytes());
            }
            let next = 0x1000 + code.len() + 6;
            code.extend([0xff, 0x15]);
            code.extend((0x2080i32 - next as i32).to_le_bytes());
        } else {
            for value in [32, base + 0x2b40, base + 0x2b00] {
                code.push(0x68);
                code.extend((value as u32).to_le_bytes());
            }
            code.extend([0xff, 0x15]);
            code.extend(((base + 0x2080) as u32).to_le_bytes());
        }
    }
    prompt(&mut code, wide, base);
    code.push(0xbb);
    code.extend(0x13572468u32.to_le_bytes());
    code.extend([0x83, 0xc0, 1, 0x90]); // Actual post-return mutation and NOP.
    if long {
        code.push(0xb9);
        code.extend(11000u32.to_le_bytes());
        code.extend([0x90, 0xff, 0xc9, 0x75, 0xfb]);
    }
    if repeat {
        prompt(&mut code, wide, base);
    }
    code.push(0xa1);
    if wide {
        code.extend((base + 0x2b40).to_le_bytes());
        code.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]);
    } else {
        code.extend(((base + 0x2b40) as u32).to_le_bytes());
        code.extend([0xc2, 8, 0]);
    }
    assert!(code.len() < 512);
    image[0x200..0x400].fill(0xcc);
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    image
}
#[test]
fn prompt_continuation_records_actual_post_return_registers_and_stops_before_next_api_once() {
    {
        let architecture = Architecture::X86;
        let e =
            run_generated_image(&fixture(architecture, true, false), 10000, 30_000_000).unwrap();
        assert_eq!(e.error, None);
        assert_eq!(e.guest_entry_return, Some(0x52525252));
        let prompt = e.kernel_prompt.as_ref().unwrap();
        assert_eq!(prompt.calls, 2);
        let window = prompt.continuation.as_ref().unwrap();
        assert_eq!(
            window.first_prompt_ordinal,
            prompt.observations[0].instruction_ordinal
        );
        assert_eq!(window.stop.as_ref().unwrap().reason, "next_api_gate");
        assert_eq!(
            window.stop.as_ref().unwrap().instruction_ordinal,
            e.api_events[1].instruction_ordinal
        );
        assert!(!window.active);
        assert!(!window.truncated);
        let rows = &window.instructions;
        assert_eq!(rows[0].instruction_ordinal, window.first_prompt_ordinal + 1);
        assert_eq!(rows[0].registers[0], 0);
        let entry = e.kernel_entry.as_ref().unwrap();
        let expected_sp = entry.layout.entry_stack + entry.entry_stack_size
            - if architecture == Architecture::X64 {
                0x108 + 0x48
            } else {
                0x10c
            };
        assert_eq!(rows[0].registers[7], expected_sp);
        assert_eq!(rows[1].registers[1], 0x13572468);
        assert_eq!(rows[2].registers[0], 1);
        assert_eq!(
            window.register_order[7],
            if architecture == Architecture::X64 {
                "rsp"
            } else {
                "esp"
            }
        );
        assert_eq!(window.register_order.last(), Some(&"eflags"));
        for pair in rows.windows(2) {
            assert_eq!(pair[1].instruction_ordinal, pair[0].instruction_ordinal + 1);
        }
        for row in rows {
            assert_eq!(
                row.registers.len(),
                if architecture == Architecture::X64 {
                    17
                } else {
                    9
                }
            );
            assert_eq!(row.thread_id, 1);
            assert_eq!(row.current_thread, e.api_events[0].current_thread);
            assert_eq!(row.execution_domain, "ordinary_thread");
            assert_eq!(row.processor, 0);
            assert!(e.api_events.iter().all(|api| row.pc != api.api_gate_pc));
            let actual = &e.instruction_tail[row.instruction_ordinal as usize];
            assert_eq!((row.pc, row.size), (actual.pc, actual.size));
        }
    }
}
#[test]
fn prompt_continuation_budget_prefixes_and_completed_native_return_are_reported_without_fabrication()
 {
    {
        let architecture = Architecture::X86;
        let image = fixture(architecture, false, false);
        let full = run_generated_image(&image, 10000, 30_000_000).unwrap();
        assert_eq!(full.guest_entry_return, Some(0x52525252));
        let prompt = full.kernel_prompt.as_ref().unwrap();
        let ordinal = prompt.observations[0].instruction_ordinal;
        let window = prompt.continuation.as_ref().unwrap();
        let last = window.instructions.last().unwrap();
        assert_eq!(last.registers[0], 0x52525252);
        assert_eq!(
            window.stop.as_ref().unwrap().run_completion,
            Some("entry_return")
        );
        assert_eq!(window.stop.as_ref().unwrap().reason, "run_stopped");
        for extra in [1, 2, 4] {
            let partial = run_generated_image(&image, ordinal + extra, 30_000_000).unwrap();
            assert_eq!(partial.error, None);
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.guest_entry_return, None);
            let window = partial.kernel_prompt.unwrap().continuation.unwrap();
            assert_eq!(window.instructions.len() as u64, extra - 1);
            assert!(window.truncated);
            assert!(!window.active);
            assert_eq!(
                window.stop.unwrap().run_completion,
                Some("instruction_budget")
            );
        }
    }
}
#[test]
fn prompt_continuation_cap_is_bounded_diagnostic_and_never_stops_the_guest() {
    {
        let architecture = Architecture::X86;
        let e =
            run_generated_image(&fixture(architecture, false, true), 100000, 30_000_000).unwrap();
        assert_eq!(e.error, None);
        assert_eq!(e.guest_entry_return, Some(0x52525252));
        let window = e
            .kernel_prompt
            .as_ref()
            .unwrap()
            .continuation
            .as_ref()
            .unwrap();
        assert_eq!(window.instructions.len(), 32768);
        assert!(window.truncated);
        assert_eq!(window.stop.as_ref().unwrap().reason, "instruction_limit");
        assert!(e.instruction_count > window.instructions.last().unwrap().instruction_ordinal);
        assert!(
            serde_json::to_vec_pretty(&e).unwrap().len() < emumee_core::reports::MAX_ENGINE_BYTES
        );
    }
}
