//! Passive native read-attempt evidence for backed initial kernel context pages.
//! A Unicorn memory hook fires before the access retires; sampled bytes are not
//! proof that the instruction consumed those bytes.
use super::*;
use emumee_core::kernel_layout::KernelLayout;
use std::cell::RefCell;

const PAGE: u64 = 4096;
const LIMIT: usize = 256;
const PREFIX: usize = 16;

#[derive(Clone, Debug, Serialize)]
pub struct Receipt {
    pub pc: Option<u64>,
    pub raw_memory_hook_instruction_count: u64,
    pub last_raw_memory_hook_instruction_count: u64,
    pub address: u64,
    pub size: usize,
    pub region: &'static str,
    pub region_base: u64,
    pub offset: u64,
    pub sampled_address: u64,
    pub sampled_prefix: Vec<u8>,
    pub sample_error: Option<&'static str>,
    pub crosses_region_boundary: bool,
    pub thread_id: u64,
    pub current_thread: u64,
    pub processor: u32,
    pub execution_domain: &'static str,
    pub repeats: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub hook_installed: bool,
    pub watched_pages: Vec<&'static str>,
    pub watched_read_attempts: u64,
    pub receipts: Vec<Receipt>,
    pub unique_limit: usize,
    pub omitted_unstored_attempts: u64,
    pub cross_boundary_attempts: u64,
    pub sample_failures: u64,
    pub pc_failures: u64,
    pub scope: &'static str,
}

#[derive(Default)]
pub(crate) struct State {
    pub(crate) rows: RefCell<Vec<Receipt>>,
    pub(crate) watched_read_attempts: std::cell::Cell<u64>,
    pub(crate) omitted_unstored_attempts: std::cell::Cell<u64>,
    pub(crate) cross_boundary_attempts: std::cell::Cell<u64>,
    pub(crate) sample_failures: std::cell::Cell<u64>,
    pub(crate) pc_failures: std::cell::Cell<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Hit {
    region: &'static str,
    base: u64,
    sampled_address: u64,
    sample_size: usize,
    crosses_boundary: bool,
}

// The DriverObject, RegistryPath, KPCR/PRCB, GDT, IDT and shared-data aliases
// are each separately backed by this engine. The root thread page and the
// descriptor TSS/lock pages are intentionally excluded.
fn classify(
    arch: Architecture,
    cpu_ready: bool,
    integrated_provider_ready: bool,
    aliases: [u64; 3],
    address: u64,
    size: usize,
) -> Option<Hit> {
    if size == 0 {
        return None;
    }
    let layout = KernelLayout::for_architecture(arch);
    let pages = [
        (layout.driver_object, "driver_object_page", true),
        (layout.registry_path, "registry_path_page", true),
        (layout.pcr, "kpcr_prcb_page", cpu_ready),
        (layout.descriptor_tables, "gdt_page", cpu_ready),
        (layout.descriptor_tables + PAGE, "idt_page", cpu_ready),
        (
            crate::api::reference_mapping::PROVIDER_BASE,
            "integrated_nt_header_page",
            integrated_provider_ready && arch == Architecture::X64,
        ),
        (aliases[0], "kuser_shared_data_user", aliases[0] != 0),
        (aliases[1], "kuser_shared_data_kernel", aliases[1] != 0),
        (aliases[2], "kuser_shared_data_compat", aliases[2] != 0),
    ];
    let end = address.saturating_add(size as u64);
    for (base, region, backed) in pages {
        if !backed || base == 0 {
            continue;
        }
        let region_end = base + PAGE;
        let first = address.max(base);
        let last = end.min(region_end);
        if first < last {
            return Some(Hit {
                region,
                base,
                sampled_address: first,
                sample_size: ((last - first) as usize).min(PREFIX),
                crosses_boundary: address < base || end > region_end,
            });
        }
    }
    None
}

pub(crate) fn observe(engine: &Unicorn<Trace>, address: u64, size: usize) {
    let trace = engine.get_data();
    if !trace.apis.kernel_mode {
        return;
    }
    let Some(hit) = classify(
        trace.architecture,
        trace.kernel_cpu.is_some(),
        !trace.reference_spans.is_empty(),
        trace.clock_aliases,
        address,
        size,
    ) else {
        return;
    };
    let state = &trace.kernel_context_reads;
    state
        .watched_read_attempts
        .set(state.watched_read_attempts.get().saturating_add(1));
    if hit.crosses_boundary {
        state
            .cross_boundary_attempts
            .set(state.cross_boundary_attempts.get().saturating_add(1));
    }
    let pc_reg = if trace.architecture == Architecture::X64 {
        RegisterX86::RIP
    } else {
        RegisterX86::EIP
    };
    let pc = engine.reg_read(pc_reg).ok();
    if pc.is_none() {
        state
            .pc_failures
            .set(state.pc_failures.get().saturating_add(1));
    }
    let thread_id = if ipi::member_running(engine) {
        0
    } else {
        threads::current_id(engine)
    };
    let current_thread = threads::thread_address(engine);
    let processor = trace.cpu.processor;
    let execution_domain = if ipi::member_running(engine) {
        "ipi_member"
    } else if threads::dpc::active(engine) {
        "dpc"
    } else {
        "ordinary_thread"
    };
    let mut rows = state.rows.borrow_mut();
    if let Some(row) = rows.iter_mut().find(|row| {
        row.pc == pc
            && row.address == address
            && row.size == size
            && row.region == hit.region
            && row.thread_id == thread_id
            && row.processor == processor
            && row.execution_domain == execution_domain
    }) {
        row.repeats = row.repeats.saturating_add(1);
        row.last_raw_memory_hook_instruction_count = trace.instructions;
        return;
    }
    if rows.len() == LIMIT {
        state
            .omitted_unstored_attempts
            .set(state.omitted_unstored_attempts.get().saturating_add(1));
        return;
    }
    let mut prefix = vec![0; hit.sample_size];
    let sample_error = if engine.mem_read(hit.sampled_address, &mut prefix).is_err() {
        prefix.clear();
        state
            .sample_failures
            .set(state.sample_failures.get().saturating_add(1));
        Some("diagnostic_mem_read_failed")
    } else {
        None
    };
    rows.push(Receipt {
        pc,
        raw_memory_hook_instruction_count: trace.instructions,
        last_raw_memory_hook_instruction_count: trace.instructions,
        address,
        size,
        region: hit.region,
        region_base: hit.base,
        offset: hit.sampled_address - hit.base,
        sampled_address: hit.sampled_address,
        sampled_prefix: prefix,
        sample_error,
        crosses_region_boundary: hit.crosses_boundary,
        thread_id,
        current_thread,
        processor,
        execution_domain,
        repeats: 0,
    });
}

pub(crate) fn report(engine: &Unicorn<Trace>) -> Report {
    let trace = engine.get_data();
    let state = &trace.kernel_context_reads;
    let mut watched_pages = vec!["driver_object_page", "registry_path_page"];
    if trace.kernel_cpu.is_some() {
        watched_pages.extend(["kpcr_prcb_page", "gdt_page", "idt_page"]);
    }
    if trace.architecture == Architecture::X64 && !trace.reference_spans.is_empty() {
        watched_pages.push("integrated_nt_header_page");
    }
    for (base, name) in trace.clock_aliases.into_iter().zip([
        "kuser_shared_data_user",
        "kuser_shared_data_kernel",
        "kuser_shared_data_compat",
    ]) {
        if base != 0 {
            watched_pages.push(name);
        }
    }
    Report {
        hook_installed: api::kernel_thread_objects::read_guard_installed(engine),
        watched_pages,
        watched_read_attempts: state.watched_read_attempts.get(),
        receipts: state.rows.borrow().clone(),
        unique_limit: LIMIT,
        omitted_unstored_attempts: state.omitted_unstored_attempts.get(),
        cross_boundary_attempts: state.cross_boundary_attempts.get(),
        sample_failures: state.sample_failures.get(),
        pc_failures: state.pc_failures.get(),
        scope: "Passive pre-retirement native MEM_READ hook attempts for backed initial DriverObject, RegistryPath, root KPCR/PRCB, GDT, IDT, KUSER_SHARED_DATA aliases and the integrated NT provider header page when present. For cross-boundary reads, only the first overlapping watched page is reported. Prefix <=16 bytes is sampled on the first attempt before the guest read; it does not prove retirement, consumption, semantic field validity or an unpacking outcome. Raw memory-hook instruction count follows the code-hook increment, so it is not a pre-code instruction ordinal. Repeats and unstored attempts are bounded; omitted_unstored_attempts can count repeats of one unstored key. Thread-private, TSS and lock-storage pages are excluded. Diagnostic failures never change guest decisions.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated_read_driver(arch: Architecture) -> Vec<u8> {
        let mut bytes = emumee_core::fixtures::counted_driver(arch, 1);
        let layout = KernelLayout::for_architecture(arch);
        let shared: u64 = if arch == Architecture::X64 {
            0xfffff78000000000
        } else {
            0xffdf0000
        };
        let mut code = if arch == Architecture::X64 {
            vec![0x8b, 0x01, 0x8b, 0x02, 0x48, 0xb8]
        } else {
            // Initial x86 DriverEntry arguments are [esp+4] and [esp+8].
            vec![
                0x8b, 0x44, 0x24, 0x04, 0x8b, 0x00, 0x8b, 0x44, 0x24, 0x08, 0x8b, 0x00, 0xb8,
            ]
        };
        code.extend_from_slice(&shared.to_le_bytes()[..arch.width()]);
        code.extend_from_slice(&[0x8b, 0x00]);
        for address in [
            layout.pcr,
            layout.descriptor_tables,
            layout.descriptor_tables + PAGE,
        ] {
            if arch == Architecture::X64 {
                code.extend_from_slice(&[0x48, 0xb8]);
            } else {
                code.push(0xb8);
            }
            code.extend_from_slice(&address.to_le_bytes()[..arch.width()]);
            code.extend_from_slice(&[0x8b, 0x00]);
        }
        code.push(0xc3);
        bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
        bytes
    }

    #[test]
    fn generated_driver_reads_are_passive_and_bound_to_initial_pages_both_widths() {
        for arch in [Architecture::X86, Architecture::X64] {
            let bytes = generated_read_driver(arch);
            let full = run_generated_image(&bytes, 1000, 30_000_000).unwrap();
            assert_eq!(full.error, None, "{arch:?}: {:#?}", full.error);
            assert_eq!(full.completion_reason, "entry_return");
            let report = full.kernel_context_reads.as_ref().unwrap();
            assert!(report.hook_installed);
            assert_eq!(report.watched_read_attempts, 6);
            assert_eq!(report.receipts.len(), 6);
            assert_eq!(report.receipts[0].region, "driver_object_page");
            assert_eq!(report.receipts[1].region, "registry_path_page");
            assert_eq!(report.receipts[2].region, "kuser_shared_data_kernel");
            assert_eq!(report.receipts[3].region, "kpcr_prcb_page");
            assert_eq!(report.receipts[4].region, "gdt_page");
            assert_eq!(report.receipts[5].region, "idt_page");
            assert!(report.receipts.iter().all(|row| row.sample_error.is_none()
                && row.sampled_prefix.len() == 4
                && row.repeats == 0));
            assert_eq!(report.omitted_unstored_attempts, 0);
            let early = run_generated_image(&bytes, 1, 30_000_000).unwrap();
            assert_eq!(early.completion_reason, "instruction_budget");
            assert_eq!(early.guest_entry_return, None);
            let early_reads = early.kernel_context_reads.as_ref().unwrap();
            assert!(early_reads.watched_read_attempts <= 1);
            assert!(early_reads.receipts.len() <= 1);
            if let Some(row) = early_reads.receipts.first() {
                assert_eq!(row.region, "driver_object_page");
            }
        }
    }

    #[test]
    fn synthetic_unmapped_attempt_and_unique_cap_are_diagnostic_only() {
        let mut native = new_engine(Architecture::X64).unwrap();
        native.get_data_mut().apis.kernel_mode = true;
        let base = KernelLayout::for_architecture(Architecture::X64).driver_object;
        observe(&native, base, 8);
        let first = report(&native);
        assert_eq!(first.sample_failures, 1);
        assert_eq!(
            first.receipts[0].sample_error,
            Some("diagnostic_mem_read_failed")
        );
        assert!(native.get_data().apis.fault.is_none());
        uc(native.mem_map(base, PAGE, Prot::READ | Prot::WRITE)).unwrap();
        for offset in 1..=260 {
            observe(&native, base + offset, 1);
        }
        let capped = report(&native);
        assert_eq!(capped.watched_read_attempts, 261);
        assert_eq!(capped.receipts.len(), LIMIT);
        assert_eq!(capped.omitted_unstored_attempts, 5);
        observe(&native, base, 8);
        let repeated = report(&native);
        assert_eq!(repeated.receipts[0].repeats, 1);
        assert!(native.get_data().apis.fault.is_none());
    }

    #[test]
    fn watched_pages_exclude_unbacked_and_private_tails_on_both_widths() {
        for arch in [Architecture::X86, Architecture::X64] {
            let layout = KernelLayout::for_architecture(arch);
            assert!(classify(arch, true, false, [0; 3], layout.driver_object, 8).is_some());
            assert!(classify(arch, true, false, [0; 3], layout.registry_path, 8).is_some());
            assert!(classify(arch, true, false, [0; 3], layout.pcr + 0x180, 8).is_some());
            assert!(classify(arch, false, false, [0; 3], layout.pcr, 8).is_none());
            for address in [
                layout.root_thread,
                layout.descriptor_tables + 8192,
                layout.descriptor_tables + 12288,
                layout.entry_stack,
            ] {
                assert!(classify(arch, true, false, [0; 3], address, 8).is_none());
            }
            let cross = classify(arch, true, false, [0; 3], layout.driver_object + 4094, 8).unwrap();
            assert!(cross.crosses_boundary);
            assert_eq!(cross.sample_size, 2);
            assert!(classify(
                arch,
                true,
                false,
                [0; 3],
                crate::api::reference_mapping::PROVIDER_BASE,
                8,
            )
            .is_none());
            let provider = classify(
                arch,
                true,
                true,
                [0; 3],
                crate::api::reference_mapping::PROVIDER_BASE + 0x3c,
                4,
            );
            assert_eq!(provider.is_some(), arch == Architecture::X64);
            if let Some(provider) = provider {
                assert_eq!(provider.region, "integrated_nt_header_page");
                assert_eq!(provider.sampled_address - provider.base, 0x3c);
            }
        }
    }
}
