//! Passive receipts for the admitted DbgPrompt model. Validation reads
//! supply the preview; reporting performs no extra guest memory reads or writes.
use super::*;

const LIMIT: usize = 64;
const PREVIEW: usize = 256;
const CONTINUATION_LIMIT: usize = 32768;
const X64_REGISTERS: &[(RegisterX86, &str)] = &[
    (RegisterX86::RAX, "rax"),
    (RegisterX86::RBX, "rbx"),
    (RegisterX86::RCX, "rcx"),
    (RegisterX86::RDX, "rdx"),
    (RegisterX86::RSI, "rsi"),
    (RegisterX86::RDI, "rdi"),
    (RegisterX86::RBP, "rbp"),
    (RegisterX86::RSP, "rsp"),
    (RegisterX86::R8, "r8"),
    (RegisterX86::R9, "r9"),
    (RegisterX86::R10, "r10"),
    (RegisterX86::R11, "r11"),
    (RegisterX86::R12, "r12"),
    (RegisterX86::R13, "r13"),
    (RegisterX86::R14, "r14"),
    (RegisterX86::R15, "r15"),
    (RegisterX86::EFLAGS, "eflags"),
];
const X86_REGISTERS: &[(RegisterX86, &str)] = &[
    (RegisterX86::EAX, "eax"),
    (RegisterX86::EBX, "ebx"),
    (RegisterX86::ECX, "ecx"),
    (RegisterX86::EDX, "edx"),
    (RegisterX86::ESI, "esi"),
    (RegisterX86::EDI, "edi"),
    (RegisterX86::EBP, "ebp"),
    (RegisterX86::ESP, "esp"),
    (RegisterX86::EFLAGS, "eflags"),
];
pub(crate) fn register_spec(architecture: Architecture) -> &'static [(RegisterX86, &'static str)] {
    if architecture == Architecture::X64 {
        X64_REGISTERS
    } else {
        X86_REGISTERS
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ContinuationInstruction {
    pub pc: u64,
    pub size: u32,
    pub instruction_ordinal: u64,
    pub registers: Vec<u64>,
    pub thread_id: u64,
    pub current_thread: u64,
    pub processor: u32,
    pub execution_domain: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct ContinuationStop {
    pub reason: &'static str,
    pub instruction_ordinal: u64,
    pub pc: Option<u64>,
    pub error: Option<String>,
    pub run_completion: Option<&'static str>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Continuation {
    pub architecture: Architecture,
    pub first_prompt_ordinal: u64,
    pub register_order: Vec<&'static str>,
    pub instructions: Vec<ContinuationInstruction>,
    pub limit: usize,
    pub active: bool,
    pub truncated: bool,
    pub stop: Option<ContinuationStop>,
    pub scope: &'static str,
}

#[derive(Default)]
pub(crate) struct State {
    calls: u64,
    observations: Vec<Observation>,
    continuation: Option<Continuation>,
    input_policy: Option<&'static str>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub arguments: [u64; 3],
    pub prompt_address: u64,
    pub response_address: u64,
    pub length: u32,
    pub prompt_bytes: usize,
    pub prompt: String,
    pub preview_truncated: bool,
    pub api_gate_pc: Option<u64>,
    pub recent_instructions: Vec<crate::TraceEntry>,
    pub instruction_ordinal: u64,
    pub thread_id: u64,
    pub current_thread: u64,
    pub processor: u32,
    pub execution_domain: &'static str,
    pub received_characters: u32,
    pub result: Option<u32>,
    pub exception_code: Option<u32>,
    pub effective_response_capacity: u16,
    pub response_writes: u32,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub calls: u64,
    pub observations: Vec<Observation>,
    pub omitted: u64,
    pub input_policy: &'static str,
    pub response_writes: u64,
    pub continuation: Option<Continuation>,
    pub scope: &'static str,
}
impl State {
    pub fn report(&self) -> Report {
        Report {
            calls: self.calls,
            observations: self.observations.clone(),
            omitted: self.calls.saturating_sub(self.observations.len() as u64),
            input_policy: self.input_policy.unwrap_or("not_observed"),
            response_writes: 0,
            continuation: self.continuation.clone(),
            scope: "Admitted DbgPrompt operations only; refusals remain in API events. AMD64 no-debugger calls raise a native breakpoint exception (service2) through the guest's registered handlers, with no normal API result or response access. x86 retains the legacy no-input normal-return model and is not qualified for kernel debugger exceptions. At most 64 receipts with 256-byte Latin-1 prompt previews and 32 recorded recent instructions. No debugger transport or answers are synthesized.",
        }
    }
    #[inline]
    pub(crate) fn continuation_active(&self) -> bool {
        self.continuation
            .as_ref()
            .is_some_and(|window| window.active)
    }
    pub fn report_at_stop(&self, completion: &'static str, ordinal: u64) -> Report {
        let mut report = self.report();
        if let Some(window) = &mut report.continuation
            && window.active
        {
            window.active = false;
            window.truncated = true;
            window.stop = Some(ContinuationStop {
                reason: "run_stopped",
                instruction_ordinal: ordinal,
                pc: None,
                error: None,
                run_completion: Some(completion),
            });
        }
        report
    }
    fn stop_continuation(&mut self, stop: ContinuationStop, truncated: bool) {
        if let Some(window) = &mut self.continuation
            && window.active
        {
            window.active = false;
            window.truncated = truncated;
            window.stop = Some(stop);
        }
    }
}
pub(crate) fn before_api(engine: &mut Unicorn<Trace>, pc: u64) {
    let ordinal = engine.get_data().instructions;
    engine.get_data_mut().apis.kernel_prompt.stop_continuation(
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
pub(crate) fn register_values(
    architecture: Architecture,
    mut read: impl FnMut(
        RegisterX86,
    ) -> std::result::Result<u64, unicorn_engine::unicorn_const::uc_error>,
) -> std::result::Result<Vec<u64>, String> {
    register_spec(architecture)
        .iter()
        .map(|(register, name)| {
            read(*register).map_err(|error| format!("Diagnostic register read {name}: {error:?}"))
        })
        .collect()
}
pub(super) fn instruction_row(
    engine: &Unicorn<Trace>,
    pc: u64,
    size: u32,
    registers: Vec<u64>,
) -> ContinuationInstruction {
    let state = engine.get_data();
    let ordinal = state.instructions;
    ContinuationInstruction {
        pc,
        size,
        instruction_ordinal: ordinal,
        registers,
        thread_id: if crate::ipi::member_running(engine) {
            0
        } else {
            crate::threads::current_id(engine)
        },
        current_thread: crate::threads::thread_address(engine),
        processor: state.cpu.processor,
        execution_domain: if crate::ipi::member_running(engine) {
            "ipi_member"
        } else if crate::threads::dpc::active(engine) {
            "dpc"
        } else {
            "ordinary_thread"
        },
    }
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
            engine.get_data_mut().apis.kernel_prompt.stop_continuation(
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
    let row = instruction_row(engine, pc, size, registers);
    let prompt = &mut engine.get_data_mut().apis.kernel_prompt;
    if let Some(window) = &mut prompt.continuation
        && window.active
    {
        window.instructions.push(row);
        if window.instructions.len() >= CONTINUATION_LIMIT {
            prompt.stop_continuation(
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
    let registers = register_values(engine.get_data().architecture, |register| {
        engine.reg_read(register)
    });
    commit_instruction(engine, pc, size, registers);
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let prompt = validate(engine, args)?;
    if engine.get_data().architecture == Architecture::X64 {
        crate::native_exceptions::api_frame::queue(
            engine,
            crate::native_exceptions::api_frame::Kind::Prompt,
        )?;
    }
    observe(engine, args, &prompt);
    Ok(0)
}
fn validate(engine: &Unicorn<Trace>, args: &[u64]) -> Result<Vec<u8>> {
    let length = args[2] as u32;
    let legacy = engine.get_data().architecture == Architecture::X86;
    if legacy {
        ensure!(length <= 512, "DbgPrompt response exceeds512 bytes");
    }
    let mut prompt = Vec::with_capacity(512);
    let mut terminated = false;
    for offset in 0..512 {
        let value = byte(
            engine,
            args[0]
                .checked_add(offset)
                .ok_or_else(|| anyhow::anyhow!("String pointer overflow"))?,
        )?;
        if value == 0 {
            terminated = true;
            break;
        }
        prompt.push(value);
    }
    ensure!(
        terminated,
        "API string is not terminated within its modeled bound"
    );
    if legacy {
        require(engine, args[1], u64::from(length), P::WRITE)?;
    }
    Ok(prompt)
}
fn observe(engine: &mut Unicorn<Trace>, args: &[u64], prompt: &[u8]) {
    let length = args[2] as u32;
    let legacy = engine.get_data().architecture == Architecture::X86;
    // These are the same metadata reads used by API event reporting. A caller
    // return address is not already decoded, so no speculative stack read occurs.
    let state = engine.get_data();
    let observation = (state.apis.kernel_prompt.observations.len() < LIMIT).then(|| Observation {
        arguments: [args[0], args[1], args[2]],
        prompt_address: args[0],
        response_address: args[1],
        length,
        prompt_bytes: prompt.len(),
        prompt: prompt
            .iter()
            .take(PREVIEW)
            .map(|value| char::from(*value))
            .collect(),
        preview_truncated: prompt.len() > PREVIEW,
        api_gate_pc: engine.pc_read().ok(),
        recent_instructions: state.tail().into_iter().rev().take(32).rev().collect(),
        instruction_ordinal: state.instructions,
        thread_id: if crate::ipi::member_running(engine) {
            0
        } else {
            crate::threads::current_id(engine)
        },
        current_thread: crate::threads::thread_address(engine),
        processor: state.cpu.processor,
        execution_domain: if crate::ipi::member_running(engine) {
            "ipi_member"
        } else if crate::threads::dpc::active(engine) {
            "dpc"
        } else {
            "ordinary_thread"
        },
        received_characters: 0,
        result: legacy.then_some(0),
        exception_code: (!legacy).then_some(0x80000003),
        effective_response_capacity: length as u16,
        response_writes: 0,
    });
    let architecture = engine.get_data().architecture;
    let ordinal = engine.get_data().instructions;
    let state = &mut engine.get_data_mut().apis.kernel_prompt;
    state.input_policy = Some(if legacy {
        "legacy_x86_no_input"
    } else {
        "no_debugger_exception"
    });
    if state.calls == 0 {
        state.continuation = Some(Continuation {
            architecture,
            first_prompt_ordinal: ordinal,
            register_order: register_spec(architecture)
                .iter()
                .map(|(_, name)| *name)
                .collect(),
            instructions: Vec::new(),
            limit: CONTINUATION_LIMIT,
            active: true,
            truncated: false,
            stop: None,
            scope: "Single passive window after the first admitted DbgPrompt operation, including guest exception dispatch on AMD64, ending before the next admitted API gate of any thread or at 32768 native instructions. Architectural GPR/EFLAGS values are pre-instruction snapshots, not retirement, call-stack or initialization-success evidence. No extra guest memory reads/writes. Run/cap stops expose incomplete windows.",
        });
    }
    state.calls = state.calls.saturating_add(1);
    if let Some(observation) = observation {
        state.observations.push(observation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Receipt unit tests deliberately test validation/metadata only. Actual
    // API admission and exception execution are covered by generated PE tests.
    fn record_metadata(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
        let prompt = validate(engine, args)?;
        observe(engine, args, &prompt);
        Ok(0)
    }
    fn engine(architecture: Architecture) -> crate::NativeEngine {
        let mut engine = crate::new_engine(architecture).unwrap();
        engine.get_data_mut().apis.kernel_mode = true;
        engine
            .mem_map(0x1000, 4096, Prot::READ | Prot::WRITE)
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(0x1000, 4096, P::RW, None, "prompt fixture")
            .unwrap();
        engine.mem_write(0x1000, b"Hello\xff\0").unwrap();
        engine.mem_write(0x1800, &[0x52; 512]).unwrap();
        engine
    }
    #[test]
    fn prompt_receipts_reuse_validation_bytes_and_preserve_no_input_effects_both_abis() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            let args = [0x1000, 0x1800, 32];
            assert_eq!(record_metadata(&mut engine, &args).unwrap(), 0);
            assert_eq!(engine.mem_read_as_vec(0x1800, 512).unwrap(), [0x52; 512]);
            let report = engine.get_data().apis.kernel_prompt.report();
            assert_eq!(report.calls, 1);
            assert_eq!(report.omitted, 0);
            assert_eq!(report.response_writes, 0);
            let observation = &report.observations[0];
            assert_eq!(observation.arguments, args);
            assert_eq!(observation.prompt, "Hello\u{ff}");
            assert_eq!(observation.prompt_bytes, 6);
            assert!(!observation.preview_truncated);
            assert_eq!(
                observation.result,
                (architecture == Architecture::X86).then_some(0)
            );
            assert_eq!(observation.received_characters, 0);
            assert_eq!(observation.response_writes, 0);
            assert_eq!(observation.thread_id, 1);
            assert_eq!(observation.execution_domain, "ordinary_thread");
        }
    }
    #[test]
    fn prompt_receipts_are_bounded_and_validation_refusals_preserve_outputs() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            engine.mem_write(0x1000, &[b'A'; 511]).unwrap();
            engine.mem_write(0x11ff, &[0]).unwrap();
            for _ in 0..65 {
                assert_eq!(
                    record_metadata(&mut engine, &[0x1000, 0x1800, 512]).unwrap(),
                    0
                );
            }
            let report = engine.get_data().apis.kernel_prompt.report();
            assert_eq!(report.calls, 65);
            assert_eq!(report.observations.len(), 64);
            assert_eq!(report.omitted, 1);
            assert!(report.observations[0].preview_truncated);
            assert_eq!(report.observations[0].prompt_bytes, 511);
            assert_eq!(report.observations[0].prompt.len(), 256);
            // Oversized length must fail before touching the invalid prompt.
            let error = record_metadata(&mut engine, &[0, 0x1800, 513]).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(if architecture == Architecture::X86 {
                        "response exceeds512"
                    } else {
                        "lacks permission"
                    })
            );
            assert!(record_metadata(&mut engine, &[0, 0x1800, 32]).is_err());
            if architecture == Architecture::X86 {
                assert!(record_metadata(&mut engine, &[0x1000, 0, 32]).is_err());
            } else {
                assert!(validate(&engine, &[0x1000, 0, 0x10020]).is_ok());
            }
            engine.mem_write(0x11ff, b"A").unwrap();
            assert!(
                record_metadata(&mut engine, &[0x1000, 0x1800, 32])
                    .unwrap_err()
                    .to_string()
                    .contains("not terminated")
            );
            assert_eq!(engine.get_data().apis.kernel_prompt.report().calls, 65);
            assert_eq!(engine.mem_read_as_vec(0x1800, 512).unwrap(), [0x52; 512]);
            // ULONG length truncation and zero-capacity NULL response are unchanged.
            engine.mem_write(0x1000, &[0]).unwrap();
            assert_eq!(
                record_metadata(&mut engine, &[0x1000, 0, 1u64 << 32]).unwrap(),
                0
            );
            assert_eq!(engine.get_data().apis.kernel_prompt.report().calls, 66);
        }
    }
    #[test]
    fn prompt_continuation_register_failure_disables_only_diagnostic_without_guest_effects() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            record_metadata(&mut engine, &[0x1000, 0x1800, 32]).unwrap();
            let failure = register_values(architecture, |_| {
                Err(unicorn_engine::unicorn_const::uc_error::READ_UNMAPPED)
            });
            commit_instruction(&mut engine, 0x4000, 1, failure);
            let report = engine.get_data().apis.kernel_prompt.report();
            let window = report.continuation.unwrap();
            assert!(!window.active);
            assert!(window.truncated);
            assert!(window.instructions.is_empty());
            let stop = window.stop.unwrap();
            assert_eq!(stop.reason, "register_read_failed");
            assert!(stop.error.unwrap().contains("Diagnostic register read"));
            assert_eq!(engine.get_data().apis.fault, None);
            assert_eq!(engine.get_data().cpu.fault, None);
            assert_eq!(engine.mem_read_as_vec(0x1800, 512).unwrap(), [0x52; 512]);
            // Further valid prompts do not start a second diagnostic window.
            record_metadata(&mut engine, &[0x1000, 0x1800, 32]).unwrap();
            assert!(!engine.get_data().apis.kernel_prompt.continuation_active());
        }
    }
}
