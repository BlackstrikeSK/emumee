//! Passive native continuation after the first completed modeled ExCreateCallback.
//! This observes CPU registers only; it does not read guest memory or alter a call.
use super::kernel_prompt::{self, ContinuationInstruction, ContinuationStop};
use super::*;

const LIMIT: usize = 65_536;

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub architecture: Architecture,
    pub first_callback_ordinal: u64,
    pub api_gate_pc: u64,
    pub result: u32,
    pub register_order: Vec<&'static str>,
    pub instructions: Vec<ContinuationInstruction>,
    pub limit: usize,
    pub active: bool,
    pub truncated: bool,
    pub stop: Option<ContinuationStop>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_stop_before_report_limit: Option<ContinuationStop>,
    pub scope: &'static str,
}

#[derive(Default)]
pub(crate) struct State {
    first: Option<Report>,
}

impl State {
    #[inline]
    pub(crate) fn active(&self) -> bool {
        self.first.as_ref().is_some_and(|window| window.active)
    }

    pub(crate) fn report_at_stop(&self, completion: &'static str, ordinal: u64) -> Option<Report> {
        let mut report = self.first.clone()?;
        if report.active {
            report.active = false;
            report.truncated = true;
            report.stop = Some(ContinuationStop {
                reason: "run_stopped",
                instruction_ordinal: ordinal,
                pc: None,
                error: None,
                run_completion: Some(completion),
            });
        }
        Some(report)
    }

    fn stop(&mut self, stop: ContinuationStop, truncated: bool) {
        if let Some(window) = &mut self.first
            && window.active
        {
            window.active = false;
            window.truncated = truncated;
            window.stop = Some(stop);
        }
    }
}

impl Report {
    pub(crate) fn trim_for_report_limit(&mut self, keep: usize) {
        if keep >= self.instructions.len() {
            return;
        }
        if self.observed_stop_before_report_limit.is_none() {
            self.observed_stop_before_report_limit = self.stop.take();
        }
        self.instructions.truncate(keep);
        let last = self.instructions.last();
        self.stop = Some(ContinuationStop {
            reason: "report_byte_limit",
            instruction_ordinal: last
                .map_or(self.first_callback_ordinal, |row| row.instruction_ordinal),
            pc: last.map(|row| row.pc),
            error: None,
            run_completion: None,
        });
        self.active = false;
        self.truncated = true;
    }
}

/// Dispatch calls this only after a modeled result and ABI return-register write
/// both succeed. Ordinary NTSTATUS failures are still completed calls.
pub(super) fn arm(engine: &mut Unicorn<Trace>, api_gate_pc: u64, result: u32) {
    let state = engine.get_data();
    if !state.apis.kernel_mode || state.apis.kernel_callback_continuation.first.is_some() {
        return;
    }
    let architecture = state.architecture;
    let ordinal = state.instructions;
    engine
        .get_data_mut()
        .apis
        .kernel_callback_continuation
        .first = Some(Report {
        architecture,
        first_callback_ordinal: ordinal,
        api_gate_pc,
        result,
        register_order: kernel_prompt::register_spec(architecture)
            .iter()
            .map(|(_, name)| *name)
            .collect(),
        instructions: Vec::new(),
        limit: LIMIT,
        active: true,
        truncated: false,
        stop: None,
        observed_stop_before_report_limit: None,
        scope: "Single passive window after the first completed modeled ExCreateCallback RET, including NTSTATUS failures; adapter-refused calls and ABI decode failures do not arm it. Ends before the next admitted API gate of any thread or after 65536 native instructions. Fixed-order architectural GPR/EFLAGS values are pre-instruction snapshots, not retirement, callback success, call-stack or unpacking evidence. Actual thread/processor/domain is recorded. No guest memory reads or writes. Diagnostic read failure only disables this window; cap/run stops expose incomplete windows.",
    });
}

pub(crate) fn before_api(engine: &mut Unicorn<Trace>, pc: u64) {
    let ordinal = engine.get_data().instructions;
    engine
        .get_data_mut()
        .apis
        .kernel_callback_continuation
        .stop(
            ContinuationStop {
                reason: "next_api_gate",
                instruction_ordinal: ordinal,
                pc: Some(pc),
                error: None,
                run_completion: None,
            },
            false,
        );
}

fn commit_instruction(
    engine: &mut Unicorn<Trace>,
    pc: u64,
    size: u32,
    registers: std::result::Result<Vec<u64>, String>,
) {
    let ordinal = engine.get_data().instructions;
    let registers = match registers {
        Ok(registers) => registers,
        Err(error) => {
            engine
                .get_data_mut()
                .apis
                .kernel_callback_continuation
                .stop(
                    ContinuationStop {
                        reason: "register_read_failed",
                        instruction_ordinal: ordinal,
                        pc: Some(pc),
                        error: Some(error),
                        run_completion: None,
                    },
                    true,
                );
            return;
        }
    };
    let row = kernel_prompt::instruction_row(engine, pc, size, registers);
    let state = &mut engine.get_data_mut().apis.kernel_callback_continuation;
    if let Some(window) = &mut state.first
        && window.active
    {
        window.instructions.push(row);
        if window.instructions.len() >= LIMIT {
            state.stop(
                ContinuationStop {
                    reason: "instruction_limit",
                    instruction_ordinal: ordinal,
                    pc: Some(pc),
                    error: None,
                    run_completion: None,
                },
                true,
            );
        }
    }
}

pub(crate) fn before_native_instruction(engine: &mut Unicorn<Trace>, pc: u64, size: u32) {
    let registers = kernel_prompt::register_values(engine.get_data().architecture, |register| {
        engine.reg_read(register)
    });
    commit_instruction(engine, pc, size, registers);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_completed_call_only_and_read_failure_is_diagnostic_only() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(arch).unwrap();
            engine.get_data_mut().apis.kernel_mode = true;
            arm(&mut engine, 0x4000, 0xc0000034);
            arm(&mut engine, 0x5000, 0);
            let failure = kernel_prompt::register_values(arch, |_| {
                Err(unicorn_engine::unicorn_const::uc_error::READ_UNMAPPED)
            });
            commit_instruction(&mut engine, 0x6000, 1, failure);
            let report = engine
                .get_data()
                .apis
                .kernel_callback_continuation
                .report_at_stop("error", 0)
                .unwrap();
            assert_eq!(report.api_gate_pc, 0x4000);
            assert_eq!(report.result, 0xc0000034);
            assert_eq!(report.instructions.len(), 0);
            assert_eq!(report.stop.unwrap().reason, "register_read_failed");
            assert_eq!(engine.get_data().apis.fault, None);
            assert_eq!(engine.get_data().cpu.fault, None);
        }
    }

    #[test]
    fn cap_stops_only_the_window_and_retains_first_call() {
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        engine.get_data_mut().apis.kernel_mode = true;
        arm(&mut engine, 0x4000, 0);
        let values = vec![0; kernel_prompt::register_spec(Architecture::X64).len()];
        for _ in 0..LIMIT {
            commit_instruction(&mut engine, 0x5000, 1, Ok(values.clone()));
        }
        let report = engine
            .get_data()
            .apis
            .kernel_callback_continuation
            .report_at_stop("entry_return", 1)
            .unwrap();
        assert_eq!(report.instructions.len(), LIMIT);
        assert!(!report.active);
        assert!(report.truncated);
        assert_eq!(report.stop.unwrap().reason, "instruction_limit");
        assert_eq!(engine.get_data().apis.fault, None);
    }
}
