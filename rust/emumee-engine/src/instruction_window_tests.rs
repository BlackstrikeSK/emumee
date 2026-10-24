use super::*;
use emumee_core::driver_input::InstructionWindow;
use emumee_core::fixtures::{ApiFixture, CallbackFixture, api_probe};
use emumee_core::kernel_layout::KernelLayout;

fn observed(bytes: &[u8], start: u64, max_records: u32, budget: u64) -> Execution {
    run_generated_with_fixture_configuration(
        bytes,
        &[],
        budget,
        30_000_000,
        GeneratedConfiguration {
            instruction_window: Some(InstructionWindow {
                start_instruction: start,
                max_records,
            }),
            ..Default::default()
        },
    )
    .unwrap()
}

fn simple(arch: Architecture) -> Vec<u8> {
    let mut image = counted_driver(arch, 1);
    let code = [0xb8, 1, 0, 0, 0, 0xbb, 2, 0, 0, 0, 0x01, 0xd8, 0xc3];
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    image
}

fn reconstruct(report: &instruction_window::Report) -> Vec<Vec<u64>> {
    let mut previous = Vec::new();
    report
        .instructions
        .iter()
        .enumerate()
        .map(|(index, row)| {
            if index == 0 {
                previous = row.full_registers.as_ref().unwrap().clone();
                assert!(row.register_deltas.is_empty());
            } else {
                assert!(row.full_registers.is_none());
                let mut last = None;
                for (register, value) in &row.register_deltas {
                    assert!(last.is_none_or(|old| old < *register));
                    assert_ne!(previous[*register as usize], *value);
                    previous[*register as usize] = *value;
                    last = Some(*register);
                }
            }
            assert_eq!(previous.len(), report.register_order.len());
            previous.clone()
        })
        .collect()
}

fn checkpoint_writer(
    checkpoint: &instruction_window::StackWritesCheckpoint,
    address: u64,
) -> kernel_stack_writes::Writer {
    checkpoint
        .last_observed_ranges
        .iter()
        .find(|range| range.address <= address && address < range.address + range.size as u64)
        .unwrap()
        .writer
}

fn final_writer(report: &kernel_stack_writes::Report, address: u64) -> kernel_stack_writes::Writer {
    report
        .last_observed_ranges
        .iter()
        .find(|range| range.address <= address && address < range.address + range.size as u64)
        .unwrap()
        .writer
}

#[test]
fn first_row_stack_checkpoint_preserves_earlier_native_writer_while_later_store_changes_final_table() {
    let code = [
        0xc7, 0x44, 0x24, 0xe0, 0x11, 0x11, 0x11, 0x11, // [SP-32] = first value
        0xc7, 0x44, 0x24, 0xe0, 0x22, 0x22, 0x22, 0x22, // Same slot = later value
        0x8b, 0x44, 0x24, 0xe0, 0xc3, // Return actual second value.
    ];
    for arch in [Architecture::X86, Architecture::X64] {
        let mut image = counted_driver(arch, 1);
        image[0x200..0x200 + code.len()].copy_from_slice(&code);
        let baseline = run_generated_image(&image, 1000, 30_000_000).unwrap();
        let execution = observed(&image, 1, 3, 1000);
        assert_eq!(execution.error, None);
        assert_eq!(execution.guest_entry_return, Some(0x2222_2222));
        assert_eq!(execution.guest_entry_return, baseline.guest_entry_return);
        let window = execution.instruction_window.as_ref().unwrap();
        assert_eq!(window.instructions[0].instruction_ordinal, 1);
        let checkpoint = window.initial_stack_writes.as_ref().unwrap();
        assert_eq!(checkpoint.observation_raw_instruction_count, 1);
        assert_eq!(checkpoint.observation_phase, "native_pre_instruction");
        assert_eq!(checkpoint.native_overlapping_attempts, 1);
        assert!(!checkpoint.frozen_before_first_callback);
        let sp = execution.kernel_entry.as_ref().unwrap().layout.entry_stack
            + execution.kernel_entry.as_ref().unwrap().entry_stack_size
            - if arch == Architecture::X64 { 0x108 } else { 0x10c };
        let first = checkpoint_writer(checkpoint, sp - 32);
        let final_report = execution.kernel_stack_writes.as_ref().unwrap();
        let later = final_writer(final_report, sp - 32);
        assert_eq!(first.source, "native_prewrite_attempt");
        assert_eq!(first.raw_instruction_count, 1);
        assert_eq!(later.raw_instruction_count, 2);
        assert!(later.sequence > first.sequence);
        assert_eq!(final_report.native_overlapping_attempts, 2);
        assert_eq!(checkpoint.native_overlapping_attempts, 1);
        assert!(checkpoint.observed_bytes >= 4);
        assert_eq!(checkpoint.observed_bytes, final_report.observed_bytes);
    }
}

#[test]
fn first_row_stack_checkpoint_copies_model_writer_once_and_marks_api_post_dispatch() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut engine = new_engine(arch).unwrap();
        engine.get_data_mut().apis.kernel_mode = true;
        let stack = KernelLayout::for_architecture(arch).entry_stack;
        uc(engine.mem_map(stack, 8192, Prot::READ | Prot::WRITE)).unwrap();
        kernel_stack_writes::install(&mut engine, stack, 8192).unwrap();
        uc(engine.mem_map(0x600000, 4096, Prot::READ | Prot::EXEC)).unwrap();
        uc(engine.mem_write(0x600000, &[0xc3])).unwrap();
        engine.get_data_mut().instruction_window =
            Some(instruction_window::State::new(InstructionWindow {
                start_instruction: 0,
                max_records: 3,
            }));
        let watched = stack + 4096;
        cpu::write(&mut engine, watched, &[0x11]).unwrap();
        instruction_window::before_instruction(&mut engine, 0x600000, 1, true);
        cpu::write(&mut engine, watched, &[0x22]).unwrap();
        engine.get_data_mut().instructions = 1;
        instruction_window::before_instruction(&mut engine, 0x600000, 1, false);
        let window = instruction_window::report(&engine, "entry_return").unwrap();
        let checkpoint = window.initial_stack_writes.as_ref().unwrap();
        assert_eq!(checkpoint.observation_raw_instruction_count, 0);
        assert_eq!(checkpoint.observation_phase, "api_post_dispatch_pre_RET");
        assert_eq!(checkpoint_writer(checkpoint, watched).sequence, 1);
        assert_eq!(checkpoint.model_overlapping_writes, 1);
        let final_report = kernel_stack_writes::report(&engine).unwrap();
        assert_eq!(final_writer(&final_report, watched).sequence, 2);
        assert_eq!(final_report.model_overlapping_writes, 2);
        assert_eq!(window.instructions.len(), 2);
        let mut value = [0];
        uc(engine.mem_read(watched, &mut value)).unwrap();
        assert_eq!(value, [0x22]);
    }
}

#[test]
fn captured_non_kernel_row_has_no_owned_stack_checkpoint() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut engine = new_engine(arch).unwrap();
        uc(engine.mem_map(0x600000, 4096, Prot::READ | Prot::EXEC)).unwrap();
        uc(engine.mem_write(0x600000, &[0xc3])).unwrap();
        engine.get_data_mut().instruction_window =
            Some(instruction_window::State::new(InstructionWindow {
                start_instruction: 0,
                max_records: 1,
            }));
        instruction_window::before_instruction(&mut engine, 0x600000, 1, false);
        let report = instruction_window::report(&engine, "entry_return").unwrap();
        assert_eq!(report.instructions.len(), 1);
        assert!(report.initial_stack_writes.is_none());
        assert!(engine.get_data().kernel_stack_writes.is_none());
    }
}

#[test]
fn first_row_pointer_samples_read_guest_bytes_once_without_mutation() {
    let mut engine = new_engine(Architecture::X64).unwrap();
    uc(engine.mem_map(0x600000, 4096, Prot::READ | Prot::EXEC)).unwrap();
    uc(engine.mem_map(0x700000, 4096, Prot::READ | Prot::WRITE)).unwrap();
    uc(engine.mem_write(0x600000, &[0xc3])).unwrap();
    let expected: Vec<u8> = (0..64).collect();
    uc(engine.mem_write(0x700000, &expected)).unwrap();
    uc(engine.reg_write(RegisterX86::R9, 0x700000)).unwrap();
    engine.get_data_mut().instruction_window =
        Some(instruction_window::State::new(InstructionWindow {
            start_instruction: 0,
            max_records: 2,
        }));

    instruction_window::before_instruction(&mut engine, 0x600000, 1, false);
    uc(engine.reg_write(RegisterX86::R9, 0x700040)).unwrap();
    engine.get_data_mut().instructions = 1;
    instruction_window::before_instruction(&mut engine, 0x600000, 1, false);

    let report = instruction_window::report(&engine, "entry_return").unwrap();
    let samples = report.first_row_pointer_samples.as_ref().unwrap();
    let r9 = samples
        .iter()
        .find(|sample| sample.register == "r9")
        .unwrap();
    assert_eq!(r9.address, 0x700000);
    assert_eq!(r9.bytes, expected);
    assert!(samples.iter().all(|sample| sample.bytes.len() == 64));
    let mut after = vec![0; 64];
    uc(engine.mem_read(0x700000, &mut after)).unwrap();
    assert_eq!(after, expected);
    assert!(engine.get_data().apis.fault.is_none());
    assert!(engine.get_data().cpu.fault.is_none());
}

#[test]
fn generated_native_rows_preserve_guest_result_exact_bytes_and_reconstruct_deltas_both_widths() {
    for arch in [Architecture::X86, Architecture::X64] {
        let image = simple(arch);
        let execution = observed(&image, 0, 4, 1000);
        assert_eq!(execution.error, None);
        assert_eq!(execution.guest_entry_return, Some(3));
        let report = execution.instruction_window.as_ref().unwrap();
        assert_eq!(report.status, "record_limit");
        assert_eq!(report.stop.reason, "record_limit");
        assert!(!report.truncated);
        let vectors = reconstruct(report);
        assert_eq!(vectors.len(), 4);
        assert_eq!(
            (vectors[1][0], vectors[2][0], vectors[2][1], vectors[3][0]),
            (1, 1, 2, 3)
        );
        let expected = [
            &image[0x200..0x205],
            &image[0x205..0x20a],
            &image[0x20a..0x20c],
            &image[0x20c..0x20d],
        ];
        for (index, (row, expected)) in report.instructions.iter().zip(expected).enumerate() {
            assert_eq!(row.instruction_ordinal, index as u64);
            assert_eq!(row.instruction_bytes, expected);
            assert_eq!(row.phase, "native_pre_instruction");
            let context = &report.contexts[row.context_id as usize];
            assert_eq!(context.thread_id, 1);
            assert_eq!(context.processor, 0);
            assert_eq!(context.execution_domain, "ordinary_thread");
        }
        assert!(
            report
                .instructions
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence)
        );
        let late = observed(&image, 1, 2, 1000);
        let late_report = late.instruction_window.as_ref().unwrap();
        assert_eq!(late_report.instructions[0].instruction_ordinal, 1);
        assert_eq!(reconstruct(late_report)[0][0], 1);
        assert_eq!(late.guest_entry_return, Some(3));
    }
}

#[test]
fn selected_api_rows_are_post_dispatch_with_actual_completed_common_memory_writes() {
    for arch in [Architecture::X86, Architecture::X64] {
        let image = api_probe(arch, ApiFixture::Callback(CallbackFixture::NamedCreate));
        let baseline = run_generated_image(&image, 2000, 30_000_000).unwrap();
        let call = baseline
            .api_events
            .iter()
            .find(|event| event.api.ends_with(".ExCreateCallback"))
            .unwrap();
        let execution = observed(&image, call.instruction_ordinal, 128, 2000);
        assert_eq!(execution.error, None);
        assert_eq!(execution.guest_entry_return, Some(1));
        assert_eq!(
            serde_json::to_value(&execution.api_events).unwrap(),
            serde_json::to_value(&baseline.api_events).unwrap()
        );
        let report = execution.instruction_window.as_ref().unwrap();
        let row = &report.instructions[0];
        assert_eq!(row.phase, "api_post_dispatch_pre_RET");
        assert_eq!(row.pc, call.api_gate_pc);
        assert_eq!(row.instruction_ordinal, call.instruction_ordinal);
        assert_eq!(row.full_registers.as_ref().unwrap()[0], 0);
        assert!(!row.instruction_bytes.is_empty());
        let write = report
            .model_writes
            .iter()
            .find(|write| {
                write.raw_instruction_count == call.instruction_ordinal
                    && write.address == call.arguments[0]
            })
            .unwrap();
        assert!(write.sequence < row.sequence);
        assert!(write.succeeded);
        assert_eq!(write.requested_bytes, arch.width());
        assert!(!write.prefix_truncated);
        let mut pointer = [0u8; 8];
        pointer[..arch.width()].copy_from_slice(&write.requested_prefix);
        let object = execution
            .kernel_callbacks
            .as_ref()
            .unwrap()
            .named
            .create_requests[0]
            .object
            .unwrap();
        assert_eq!(u64::from_le_bytes(pointer), object);
        assert!(report.model_write_records_omitted == 0);
    }
}

#[test]
fn budget_prefix_and_not_reached_windows_never_invent_later_snapshots_or_returns() {
    for arch in [Architecture::X86, Architecture::X64] {
        let image = simple(arch);
        let early = observed(&image, 0, 8, 2);
        assert_eq!(early.error, None);
        assert_eq!(early.completion_reason, "instruction_budget");
        assert_eq!(early.guest_entry_return, None);
        let report = early.instruction_window.unwrap();
        assert_eq!(report.status, "prefix");
        assert_eq!(report.instructions.len(), 2);
        assert!(report.truncated);
        let missed = observed(&image, 100, 4, 1000);
        assert_eq!(missed.guest_entry_return, Some(3));
        let report = missed.instruction_window.unwrap();
        assert_eq!(report.status, "not_reached");
        assert!(report.instructions.is_empty());
        assert!(report.initial_stack_writes.is_none());
        assert_eq!(report.model_write_calls, 0);
    }
}

#[test]
fn failed_diagnostic_instruction_read_stops_observation_without_guest_fault_or_new_rows() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut engine = new_engine(arch).unwrap();
        engine.get_data_mut().instruction_window =
            Some(instruction_window::State::new(InstructionWindow {
                start_instruction: 10,
                max_records: 4,
            }));
        instruction_window::before_instruction(&mut engine, 0x600000, 1, false);
        assert_eq!(
            instruction_window::report(&engine, "instruction_budget")
                .unwrap()
                .status,
            "not_reached"
        );
        engine.get_data_mut().instructions = 10;
        instruction_window::before_instruction(&mut engine, 0x600000, 1, false);
        let report = instruction_window::report(&engine, "entry_return").unwrap();
        assert_eq!(report.status, "diagnostic_failure");
        assert_eq!(report.stop.reason, "instruction_bytes_read_failed");
        assert!(report.instructions.is_empty());
        assert!(report.initial_stack_writes.is_none());
        assert!(engine.get_data().apis.fault.is_none());
        assert!(engine.get_data().cpu.fault.is_none());
        uc(engine.mem_map(0x600000, 4096, Prot::READ | Prot::EXEC)).unwrap();
        uc(engine.mem_write(0x600000, &[0x90])).unwrap();
        instruction_window::before_instruction(&mut engine, 0x600000, 1, false);
        assert!(
            instruction_window::report(&engine, "entry_return")
                .unwrap()
                .instructions
                .is_empty()
        );
        // Exercise the diagnostic table bound with explicit selected logical
        // contexts; no guest instruction or hardware value is synthesized.
        engine.get_data_mut().instruction_window =
            Some(instruction_window::State::new(InstructionWindow {
                start_instruction: 10,
                max_records: 1024,
            }));
        for processor in 0..=256 {
            engine.get_data_mut().instructions = 10 + processor as u64;
            engine.get_data_mut().cpu.processor = processor;
            instruction_window::before_instruction(&mut engine, 0x600000, 1, false);
        }
        let capped = instruction_window::report(&engine, "entry_return").unwrap();
        assert_eq!(capped.status, "diagnostic_failure");
        assert_eq!(capped.stop.reason, "context_limit");
        assert_eq!(capped.context_limit, 256);
        assert_eq!(capped.contexts.len(), 256);
        assert_eq!(capped.instructions.len(), 256);
        assert!(
            capped
                .instructions
                .iter()
                .all(|row| (row.context_id as usize) < capped.contexts.len())
        );
        assert!(engine.get_data().apis.fault.is_none());
        assert!(engine.get_data().cpu.fault.is_none());
    }
}

#[test]
fn model_write_prefix_and_record_bounds_preserve_success_and_failed_partial_unknown_results() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut engine = new_engine(arch).unwrap();
        uc(engine.mem_map(0x600000, 4096, Prot::READ | Prot::WRITE)).unwrap();
        engine.get_data_mut().instruction_window =
            Some(instruction_window::State::new(InstructionWindow {
                start_instruction: 0,
                max_records: 4,
            }));
        let bytes: Vec<_> = (0..300).map(|value| value as u8).collect();
        cpu::write(&mut engine, 0x600000, &bytes).unwrap();
        assert!(cpu::write(&mut engine, 0x600ffe, &[1, 2, 3, 4]).is_err());
        for _ in 0..4095 {
            cpu::write(&mut engine, 0x600000, &[7]).unwrap();
        }
        let report = instruction_window::report(&engine, "entry_return").unwrap();
        assert_eq!(report.model_write_calls, 4097);
        assert_eq!(report.model_write_record_limit, 4096);
        assert_eq!(report.model_writes.len(), 4096);
        assert_eq!(report.model_write_records_omitted, 1);
        assert_eq!(report.model_write_bytes_omitted, 45);
        assert_eq!(report.model_writes[0].requested_prefix, bytes[..256]);
        assert_eq!(report.model_writes[0].requested_bytes, 300);
        assert!(report.model_writes[0].prefix_truncated);
        assert!(report.model_writes[0].succeeded);
        assert!(!report.model_writes[1].succeeded);
        assert_eq!(
            report.model_writes[1].effect,
            "backend_mem_write_failed_partial_effects_unknown"
        );
        assert_eq!(report.model_writes[1].requested_prefix, [1, 2, 3, 4]);
        assert_eq!(report.model_writes.last().unwrap().requested_prefix, [7]);
        assert!(report.model_writes.last().unwrap().succeeded);
        assert!(
            report
                .model_writes
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence)
        );
        assert!(engine.get_data().apis.fault.is_none());
    }
}
