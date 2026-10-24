use super::*;
use emumee_core::fixtures::{ApiFixture, CallbackFixture as F, api_probe};

fn generated(arch: Architecture, kind: F, budget: u64) -> Execution {
    run_generated_image(
        &api_probe(arch, ApiFixture::Callback(kind)),
        budget,
        30_000_000,
    )
    .unwrap()
}

#[test]
fn first_completed_create_records_native_preinstruction_prefix_to_next_api() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = generated(arch, F::NamedReopen, 2000);
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        let calls = result
            .api_events
            .iter()
            .filter(|event| event.api.ends_with(".ExCreateCallback"))
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 2, "api events: {:#?}", result.api_events);
        let window = result.kernel_callback_continuation.as_ref().unwrap();
        assert_eq!(window.first_callback_ordinal, calls[0].instruction_ordinal);
        assert_eq!(window.api_gate_pc, calls[0].api_gate_pc);
        assert_eq!(window.result, calls[0].result.unwrap() as u32);
        assert_eq!(window.limit, 65_536);
        assert!(!window.active);
        assert!(!window.truncated);
        assert_eq!(window.stop.as_ref().unwrap().reason, "next_api_gate");
        let next = result
            .api_events
            .iter()
            .find(|event| event.instruction_ordinal > calls[0].instruction_ordinal)
            .unwrap();
        assert_eq!(
            window.stop.as_ref().unwrap().instruction_ordinal,
            next.instruction_ordinal
        );
        assert_eq!(window.stop.as_ref().unwrap().pc, Some(next.api_gate_pc));
        assert!(!window.instructions.is_empty());
        assert_eq!(
            window.instructions[0].registers[0],
            calls[0].result.unwrap()
        );
        assert_eq!(
            window.instructions[0].instruction_ordinal,
            calls[0].instruction_ordinal + 1
        );
        assert_eq!(window.register_order.last(), Some(&"eflags"));
        assert_eq!(
            window.register_order.len(),
            if arch == Architecture::X64 { 17 } else { 9 }
        );
        for row in &window.instructions {
            assert_eq!(row.registers.len(), window.register_order.len());
            assert_eq!(row.thread_id, 1);
            assert_eq!(row.processor, 0);
            assert_eq!(row.execution_domain, "ordinary_thread");
            assert!(
                result
                    .api_events
                    .iter()
                    .all(|event| row.pc != event.api_gate_pc)
            );
        }
        for pair in window.instructions.windows(2) {
            assert_eq!(pair[1].instruction_ordinal, pair[0].instruction_ordinal + 1);
        }
    }
}

#[test]
fn ordinary_name_not_found_arms_but_refused_call_does_not() {
    for arch in [Architecture::X86, Architecture::X64] {
        let missing = generated(arch, F::NamedMissing, 2000);
        assert_eq!(missing.error, None);
        let window = missing.kernel_callback_continuation.unwrap();
        assert_eq!(
            window.result,
            emumee_core::kernel_callbacks::STATUS_OBJECT_NAME_NOT_FOUND
        );
        assert!(!window.instructions.is_empty());
        assert_eq!(window.stop.as_ref().unwrap().reason, "run_stopped");
        assert_eq!(
            window.stop.as_ref().unwrap().run_completion,
            Some("entry_return")
        );
        let refused = generated(arch, F::NamedSecurity, 2000);
        assert!(refused.error.is_some());
        assert!(
            refused.kernel_callback_continuation.is_none(),
            "error={:?}; events={:#?}; continuation={:#?}",
            refused.error,
            refused.api_events,
            refused.kernel_callback_continuation
        );
    }
}

#[test]
fn budget_is_only_a_diagnostic_prefix_and_never_invents_return() {
    for arch in [Architecture::X86, Architecture::X64] {
        let full = generated(arch, F::NamedCreate, 2000);
        assert_eq!(full.error, None);
        let window = full.kernel_callback_continuation.unwrap();
        let ordinal = window.first_callback_ordinal;
        for extra in [1, 2, 4] {
            let partial = generated(arch, F::NamedCreate, ordinal + extra);
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.error, None);
            assert_eq!(partial.guest_entry_return, None);
            let report = partial.kernel_callback_continuation.unwrap();
            assert_eq!(report.first_callback_ordinal, ordinal);
            assert_eq!(report.instructions.len() as u64, extra - 1);
            assert!(report.truncated);
            assert_eq!(report.stop.as_ref().unwrap().reason, "run_stopped");
            assert_eq!(
                report.stop.as_ref().unwrap().run_completion,
                Some("instruction_budget")
            );
        }
    }
}

#[test]
fn combined_prompt_and_callback_compact_report_respects_worker_byte_bound() {
    use crate::api::kernel_prompt::{Continuation, ContinuationInstruction};

    fn filled(max_registers: bool) -> Execution {
        let mut result = generated(Architecture::X64, F::NamedCreate, 2000);
        let mut row: ContinuationInstruction = result
            .kernel_callback_continuation
            .as_ref()
            .unwrap()
            .instructions[0]
            .clone();
        if max_registers {
            row.registers.fill(u64::MAX);
            row.pc = u64::MAX;
            row.instruction_ordinal = u64::MAX;
            row.current_thread = u64::MAX;
            row.thread_id = u64::MAX;
            row.processor = u32::MAX;
        }
        let callback_rows = if max_registers { 65_536 } else { 59_034 };
        let prompt_rows = if max_registers { 32_768 } else { 22_195 };
        let order = result
            .kernel_callback_continuation
            .as_ref()
            .unwrap()
            .register_order
            .clone();
        result
            .kernel_callback_continuation
            .as_mut()
            .unwrap()
            .instructions = vec![row.clone(); callback_rows];
        result.kernel_prompt.as_mut().unwrap().continuation = Some(Continuation {
            architecture: Architecture::X64,
            first_prompt_ordinal: 0,
            register_order: order,
            instructions: vec![row; prompt_rows],
            limit: 32_768,
            active: false,
            truncated: false,
            stop: None,
            scope: "generated size fixture",
        });
        result
    }

    let mut realistic = filled(false);
    let before = serde_json::to_vec(&realistic).unwrap().len();
    assert!(before < emumee_core::reports::MAX_ENGINE_BYTES);
    bound_callback_continuation_report(&mut realistic);
    let window = realistic.kernel_callback_continuation.unwrap();
    assert_eq!(window.instructions.len(), 59_034);
    assert_ne!(window.stop.unwrap().reason, "report_byte_limit");

    let mut worst = filled(true);
    assert!(serde_json::to_vec(&worst).unwrap().len() > emumee_core::reports::MAX_ENGINE_BYTES);
    bound_callback_continuation_report(&mut worst);
    assert_eq!(
        worst
            .kernel_prompt
            .as_ref()
            .unwrap()
            .continuation
            .as_ref()
            .unwrap()
            .instructions
            .len(),
        32_768
    );
    let window = worst.kernel_callback_continuation.as_ref().unwrap();
    assert!(window.instructions.len() < 65_536);
    assert_eq!(window.stop.as_ref().unwrap().reason, "report_byte_limit");
    assert!(window.observed_stop_before_report_limit.is_some());
    assert!(serde_json::to_vec(&worst).unwrap().len() < emumee_core::reports::MAX_ENGINE_BYTES);
}
