use super::*;
use emumee_core::fixtures::{ApiFixture, CallbackFixture, counted_driver};
use emumee_core::kernel_layout::KernelLayout;

fn generated(arch: Architecture, code: &[u8], budget: u64) -> Execution {
    let mut image = counted_driver(arch, 1);
    assert!(code.len() < 512);
    image[0x200..0x400].fill(0xcc);
    image[0x200..0x200 + code.len()].copy_from_slice(code);
    run_generated_image(&image, budget, 30_000_000).unwrap()
}

fn at(report: &kernel_stack_writes::Report, address: u64) -> kernel_stack_writes::Writer {
    report
        .last_observed_ranges
        .iter()
        .find(|range| range.address <= address && address < range.address + range.size as u64)
        .unwrap_or_else(|| panic!("No writer for {address:#x}: {report:#?}"))
        .writer
}

fn address_code(arch: Architecture, address: u64) -> Vec<u8> {
    let mut code = if arch == Architecture::X64 {
        vec![0x48, 0xb8]
    } else {
        vec![0xb8]
    };
    code.extend_from_slice(&address.to_le_bytes()[..arch.width()]);
    code.extend([0xc7, 0x00, 0x78, 0x56, 0x34, 0x12, 0x8b, 0x00, 0xc3]);
    code
}

const OVERLAP: &[u8] = &[
    0xc7, 0x44, 0x24, 0xe0, 0x44, 0x33, 0x22, 0x11, // DWORD [SP-32]=11223344
    0xc7, 0x44, 0x24, 0xe0, 0x44, 0x33, 0x22, 0x11, // Identical second store.
    0x66, 0xc7, 0x44, 0x24, 0xe2, 0x66, 0x55, // WORD [SP-30]=5566
    0x8b, 0x44, 0x24, 0xe0, 0xc3, // Guest independently returns resulting DWORD.
];

#[test]
fn native_identical_and_byte_overlapping_stores_preserve_actual_guest_result_both_widths() {
    for arch in [Architecture::X86, Architecture::X64] {
        let execution = generated(arch, OVERLAP, 1000);
        assert_eq!(execution.error, None);
        assert_eq!(execution.completion_reason, "entry_return");
        assert_eq!(execution.guest_entry_return, Some(0x55663344));
        let entry = execution.kernel_entry.as_ref().unwrap();
        let sp = entry.layout.entry_stack + entry.entry_stack_size
            - if arch == Architecture::X64 {
                0x108
            } else {
                0x10c
            };
        let report = execution.kernel_stack_writes.as_ref().unwrap();
        assert_eq!(report.native_overlapping_attempts, 3);
        assert!(!report.frozen_before_first_callback);
        let low = at(report, sp - 32);
        let high = at(report, sp - 30);
        let image = &execution.image_load;
        assert_eq!(low.pc, Some(image.base + 0x1000 + 8));
        assert_eq!(high.pc, Some(image.base + 0x1000 + 16));
        assert_eq!(
            (low.raw_instruction_count, high.raw_instruction_count),
            (2, 3)
        );
        assert!(high.sequence > low.sequence);
        for writer in [low, high] {
            assert_eq!(writer.source, "native_prewrite_attempt");
            assert_eq!(writer.thread_id, 1);
            assert_eq!(writer.current_thread, entry.layout.root_thread);
            assert_eq!(writer.processor, 0);
            assert_eq!(writer.execution_domain, "ordinary_thread");
        }
    }
}

#[test]
fn native_store_starting_in_previous_stack_page_is_observed_without_changing_value() {
    for arch in [Architecture::X86, Architecture::X64] {
        let layout = KernelLayout::for_architecture(arch);
        let page = layout.entry_stack + STACK_SIZE - 4096;
        let execution = generated(arch, &address_code(arch, page - 2), 1000);
        assert_eq!(execution.error, None);
        assert_eq!(execution.guest_entry_return, Some(0x12345678));
        let report = execution.kernel_stack_writes.as_ref().unwrap();
        assert_eq!(report.native_hook_start, layout.entry_stack);
        assert_eq!(report.watched_page, page);
        assert!(report.native_overlapping_attempts > 0);
        assert_eq!(at(report, page).source, "native_prewrite_attempt");
        assert_eq!(at(report, page + 1).source, "native_prewrite_attempt");
        assert!(
            report
                .last_observed_ranges
                .iter()
                .all(|range| range.address >= page)
        );
    }
}

#[test]
fn model_write_success_and_failed_possible_partial_effects_are_distinct_and_bounded() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut engine = new_engine(arch).unwrap();
        engine.get_data_mut().apis.kernel_mode = true;
        let stack = KernelLayout::for_architecture(arch).entry_stack;
        uc(engine.mem_map(stack, 8192, Prot::READ | Prot::WRITE)).unwrap();
        kernel_stack_writes::install(&mut engine, stack, 8192).unwrap();
        cpu::write(&mut engine, stack + 4096, &[0x5a; 4096]).unwrap();
        let succeeded = kernel_stack_writes::report(&engine).unwrap();
        assert_eq!(succeeded.observed_bytes, 4096);
        assert_eq!(succeeded.native_overlapping_attempts, 0);
        assert_eq!(succeeded.model_overlapping_writes, 1);
        assert_eq!(
            at(&succeeded, stack + 4096).source,
            "model_mem_write_succeeded"
        );
        let mut actual = [0u8; 4];
        uc(engine.mem_read(stack + 4096, &mut actual)).unwrap();
        assert_eq!(actual, [0x5a; 4]);
        assert!(cpu::write(&mut engine, stack + 8190, &[1, 2, 3, 4]).is_err());
        let failed = kernel_stack_writes::report(&engine).unwrap();
        assert_eq!(failed.observed_bytes, 4096);
        assert_eq!(failed.model_overlapping_writes, 2);
        assert_eq!(
            at(&failed, stack + 8190).source,
            "model_mem_write_failed_partial_effects_unknown"
        );
        assert!(failed.last_observed_ranges.len() <= 4096);
        assert_eq!(
            failed
                .last_observed_ranges
                .iter()
                .map(|range| range.size)
                .sum::<usize>(),
            4096
        );
        assert!(engine.get_data().apis.fault.is_none());
        // A failed native write may have partial effects: no byte value is
        // inferred or asserted for the failing span.
    }
}

#[test]
fn first_callback_freezes_before_adapter_effects_and_later_native_mutation_both_widths() {
    for arch in [Architecture::X86, Architecture::X64] {
        let image = emumee_core::fixtures::api_probe(
            arch,
            ApiFixture::Callback(CallbackFixture::NamedReopen),
        );
        let full = run_generated_image(&image, 2000, 30_000_000).unwrap();
        assert_eq!(full.error, None);
        assert_eq!(full.guest_entry_return, Some(1));
        let first = full
            .api_events
            .iter()
            .find(|event| event.api.ends_with(".ExCreateCallback"))
            .unwrap();
        let frozen = full.kernel_stack_writes.as_ref().unwrap();
        assert!(frozen.frozen_before_first_callback);
        assert_eq!(
            frozen.freeze_instruction_count,
            Some(first.instruction_ordinal)
        );
        assert!(full.instruction_count > first.instruction_ordinal + 1);
        let before = run_generated_image(&image, first.instruction_ordinal, 30_000_000).unwrap();
        assert_eq!(before.completion_reason, "instruction_budget");
        assert_eq!(before.guest_entry_return, None);
        let prefix = before.kernel_stack_writes.as_ref().unwrap();
        assert!(!prefix.frozen_before_first_callback);
        assert_eq!(
            serde_json::to_value(&prefix.last_observed_ranges).unwrap(),
            serde_json::to_value(&frozen.last_observed_ranges).unwrap()
        );
        assert_eq!(
            prefix.native_overlapping_attempts,
            frozen.native_overlapping_attempts
        );
        assert_eq!(
            prefix.model_overlapping_writes,
            frozen.model_overlapping_writes
        );
    }
}

#[test]
fn faulting_write_attempt_and_budget_prefix_do_not_claim_completion() {
    for arch in [Architecture::X86, Architecture::X64] {
        let layout = KernelLayout::for_architecture(arch);
        let execution = generated(
            arch,
            &address_code(arch, layout.entry_stack + STACK_SIZE - 2),
            1000,
        );
        assert_eq!(execution.completion_reason, "error");
        assert!(execution.error.is_some());
        assert_eq!(execution.guest_entry_return, None);
        let report = execution.kernel_stack_writes.as_ref().unwrap();
        let writer = at(report, layout.entry_stack + STACK_SIZE - 2);
        assert_eq!(writer.source, "native_prewrite_attempt");
        assert!(writer.raw_instruction_count <= execution.instruction_count);
        assert!(report.observed_bytes <= 4096);
        let early = generated(arch, OVERLAP, 1);
        assert_eq!(early.error, None);
        assert_eq!(early.completion_reason, "instruction_budget");
        assert_eq!(early.guest_entry_return, None);
        assert_eq!(
            early
                .kernel_stack_writes
                .unwrap()
                .native_overlapping_attempts,
            1
        );
    }
}
