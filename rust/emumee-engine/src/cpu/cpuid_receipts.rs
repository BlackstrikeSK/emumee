//! Completed modeled CPUID output receipts, with no additional guest/host reads.
//! The existing model's four register writes precede this passive publication.
use super::*;

const LIMIT: usize = 64;

#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub function: u32,
    pub subleaf: u32,
    pub processor: u32,
    /// Existing modeled output order is EAX, EBX, ECX, EDX.
    pub outputs: [u32; 4],
    pub pc: u64,
    pub instruction_count: u64,
    pub architecture: Architecture,
    pub thread_id: u64,
    pub current_thread: u64,
    pub execution_domain: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub completed_calls: u64,
    pub limit: usize,
    pub observations: Vec<Observation>,
    pub omitted_calls: u64,
    pub output_register_order: [&'static str; 4],
    pub scope: &'static str,
}

pub(super) fn record(
    engine: &mut Unicorn<Trace>,
    pc: u64,
    function: u32,
    subleaf: u32,
    outputs: [u32; 4],
) {
    let state = engine.get_data();
    let observation = Observation {
        function,
        subleaf,
        processor: state.cpu.processor,
        outputs,
        pc,
        instruction_count: state.instructions,
        architecture: state.architecture,
        thread_id: if crate::ipi::member_running(engine) {
            0
        } else {
            crate::threads::current_id(engine)
        },
        current_thread: crate::threads::thread_address(engine),
        execution_domain: if crate::ipi::member_running(engine) {
            "ipi_member"
        } else if crate::threads::dpc::active(engine) {
            "dpc"
        } else {
            "ordinary_thread"
        },
    };
    let cpu = &mut engine.get_data_mut().cpu.report;
    let report = cpu.cpuid_receipts.get_or_insert_with(|| Report {
        completed_calls: 0,
        limit: LIMIT,
        observations: Vec::new(),
        omitted_calls: 0,
        output_register_order: ["eax", "ebx", "ecx", "edx"],
        scope: "Passive receipts after all four existing modeled CPUID register writes succeed. Inputs are the existing low32 function/subleaf reads and outputs are the exact existing modeled EAX/EBX/ECX/EDX values, without host queries or additional guest reads. The existing cpuid counter is the completed-write call authority; at most64 initial receipts, with omitted completed calls counted. Instruction count includes current code-hook admission. Context is the actual selected modeled thread/processor/domain. Completed writes do not prove RET, retirement, driver initialization, a rejection cause or unpacking; CPU values, policy, time and guest decisions are unchanged. The optional report is omitted when no CPUID register-write set completed.",
    });
    report.completed_calls = cpu.cpuid;
    if report.observations.len() < LIMIT {
        report.observations.push(observation);
    } else {
        report.omitted_calls = report.omitted_calls.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::fixtures::{ApiFixture, CpuFixture, IpiFixture, counted_driver};

    fn driver(architecture: Architecture, code: &[u8]) -> Vec<u8> {
        let mut bytes = counted_driver(architecture, 1);
        bytes[0x200..0x200 + code.len()].copy_from_slice(code);
        bytes
    }

    #[test]
    fn completed_modeled_cpuid_receipts_match_guest_asserted_results_and_context_both_widths() {
        for architecture in [Architecture::X86, Architecture::X64] {
            // The existing guest probe independently checks vendor/signature,
            // topology/frequency/unknown values and x64 cleared upper halves.
            let result = crate::run_cpu_fixture(architecture, CpuFixture::Identity, 1000).unwrap();
            assert_eq!(result.error, None);
            assert_eq!(result.guest_entry_return, Some(1));
            let report = result.cpu.cpuid_receipts.as_ref().unwrap();
            assert_eq!(report.completed_calls, result.cpu.cpuid);
            assert_eq!(report.completed_calls, 5);
            assert_eq!(report.limit, LIMIT);
            assert_eq!(report.omitted_calls, 0);
            assert_eq!(report.output_register_order, ["eax", "ebx", "ecx", "edx"]);
            assert_eq!(
                report
                    .observations
                    .iter()
                    .map(|row| (row.function, row.subleaf))
                    .collect::<Vec<_>>(),
                [(0, 0), (1, 0), (0xb, 1), (0x16, 0), (0x40000000, 0)]
            );
            for row in &report.observations {
                assert_eq!(row.architecture, architecture);
                assert_eq!(row.processor, 0);
                assert_eq!(row.thread_id, 1);
                assert_eq!(
                    row.current_thread,
                    emumee_core::kernel_layout::KernelLayout::for_architecture(architecture)
                        .root_thread
                );
                assert_eq!(row.execution_domain, "ordinary_thread");
                assert_eq!(
                    row.outputs,
                    CpuProfile::default().leaf(row.function, row.subleaf, 0)
                );
                assert!(
                    (result.image_load.base
                        ..result.image_load.base + u64::from(result.image_load.size))
                        .contains(&row.pc)
                );
                assert!(
                    row.instruction_count > 0 && row.instruction_count < result.instruction_count
                );
            }
            assert!(
                report
                    .observations
                    .windows(2)
                    .all(|pair| pair[0].instruction_count < pair[1].instruction_count)
            );
        }
    }

    #[test]
    fn cpuid_receipts_preserve_actual_ipi_processor_and_borrowed_thread_contexts() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let result =
                crate::run_api_fixture(architecture, ApiFixture::Ipi(IpiFixture::Four), 20000)
                    .unwrap();
            assert_eq!(result.error, None);
            assert_eq!(result.guest_entry_return, Some(1));
            let report = result.cpu.cpuid_receipts.as_ref().unwrap();
            assert_eq!(report.completed_calls, result.cpu.cpuid);
            assert_eq!(report.completed_calls, 8);
            assert_eq!(report.omitted_calls, 0);
            for row in &report.observations {
                assert_eq!(row.thread_id, 0);
                assert_eq!(row.execution_domain, "ipi_member");
                assert!(row.processor < 4);
                let layout =
                    emumee_core::ipi::processor_layout(architecture, row.processor).unwrap();
                let thread = layout.parked_thread.unwrap_or_else(|| {
                    emumee_core::kernel_layout::KernelLayout::for_architecture(architecture)
                        .root_thread
                });
                assert_eq!(row.current_thread, thread);
                if row.function == 0xb {
                    assert_eq!(row.outputs[3], row.processor);
                } else {
                    assert_eq!((row.function, row.subleaf), (1, 0));
                    assert_eq!(row.outputs[1] >> 24, row.processor);
                }
            }
        }
    }

    #[test]
    fn bounded_receipts_count_completed_queries_and_preserve_budget_boundaries() {
        for architecture in [Architecture::X86, Architecture::X64] {
            // ESI survives CPUID, retaining a real guest loop count of65.
            let code = [
                0x56, 0xbe, 65, 0, 0, 0, 0x31, 0xc0, 0x31, 0xc9, 0x0f, 0xa2, 0xff, 0xce, 0x75,
                0xf6, 0xb8, 1, 0, 0, 0, 0x5e, 0xc3,
            ];
            let result =
                crate::run_generated_image(&driver(architecture, &code), 1000, 30_000_000).unwrap();
            assert_eq!(result.error, None);
            assert_eq!(result.guest_entry_return, Some(1));
            let report = result.cpu.cpuid_receipts.as_ref().unwrap();
            assert_eq!(result.cpu.cpuid, 65);
            assert_eq!(report.completed_calls, 65);
            assert_eq!(report.observations.len(), LIMIT);
            assert_eq!(report.omitted_calls, 1);
            assert!(
                report
                    .observations
                    .iter()
                    .all(|row| (row.function, row.subleaf) == (0, 0))
            );

            let prefix = driver(architecture, &[0x31, 0xc0, 0x31, 0xc9, 0x0f, 0xa2, 0xc3]);
            let before = crate::run_generated_image(&prefix, 2, 30_000_000).unwrap();
            assert_eq!(before.completion_reason, "instruction_budget");
            assert_eq!(before.cpu.cpuid, 0);
            assert!(before.cpu.cpuid_receipts.is_none());
            assert!(
                serde_json::to_value(&before.cpu)
                    .unwrap()
                    .get("cpuid_receipts")
                    .is_none()
            );
            let after = crate::run_generated_image(&prefix, 3, 30_000_000).unwrap();
            assert_eq!(after.completion_reason, "instruction_budget");
            assert_eq!(after.guest_entry_return, None);
            assert_eq!(after.cpu.cpuid, 1);
            assert_eq!(
                after.cpu.cpuid_receipts.as_ref().unwrap().completed_calls,
                1
            );
            assert_eq!(
                after
                    .cpu
                    .cpuid_receipts
                    .as_ref()
                    .unwrap()
                    .observations
                    .len(),
                1
            );
        }
    }
}
