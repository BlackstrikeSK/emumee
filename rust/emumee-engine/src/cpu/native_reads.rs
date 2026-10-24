//! Passive receipts for native, non-CR8 control-register and non-TSC MSR reads.
//! Values are sampled only at the exact next instruction in the same context.
use super::*;

const LIMIT: usize = 256;

#[derive(Clone, Debug, Serialize)]
pub struct ReadAttempt {
    pub pc: u64,
    pub size: u32,
    pub kind: &'static str,
    pub control_register: Option<u8>,
    pub msr_index: Option<u32>,
    pub instruction_count: u64,
    pub architecture: Architecture,
    pub thread_id: u64,
    pub current_thread: u64,
    pub processor: u32,
    pub execution_domain: &'static str,
    pub destination: &'static str,
    pub backend: &'static str,
    pub completion: &'static str,
    pub observed_value: Option<u64>,
    pub observation_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub attempts: Vec<ReadAttempt>,
    pub limit: usize,
    pub omitted_attempts: u64,
    pub observation_failures: u64,
    pub scope: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Context {
    architecture: Architecture,
    thread_id: u64,
    current_thread: u64,
    processor: u32,
    execution_domain: &'static str,
}

#[derive(Clone, Copy)]
enum Destination {
    Control(RegisterX86),
    Msr,
}

struct Pending {
    row: usize,
    next_pc: u64,
    context: Context,
    destination: Destination,
}

struct ArmSpec {
    kind: &'static str,
    control_register: Option<u8>,
    msr_index: Option<u32>,
    destination: Destination,
    destination_name: &'static str,
    backend: &'static str,
}

#[derive(Default)]
pub(crate) struct State {
    attempts: Vec<ReadAttempt>,
    omitted_attempts: u64,
    observation_failures: u64,
    pending: Option<Pending>,
}

impl State {
    #[inline]
    pub(crate) fn pending(&self) -> bool {
        self.pending.is_some()
    }
}

fn context(engine: &Unicorn<Trace>) -> Context {
    let state = engine.get_data();
    Context {
        architecture: state.architecture,
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

fn register(architecture: Architecture, index: u8) -> Option<(RegisterX86, &'static str)> {
    let wide = architecture == Architecture::X64;
    let registers = [
        (RegisterX86::RAX, "rax"),
        (RegisterX86::RCX, "rcx"),
        (RegisterX86::RDX, "rdx"),
        (RegisterX86::RBX, "rbx"),
        (RegisterX86::RSP, "rsp"),
        (RegisterX86::RBP, "rbp"),
        (RegisterX86::RSI, "rsi"),
        (RegisterX86::RDI, "rdi"),
        (RegisterX86::R8, "r8"),
        (RegisterX86::R9, "r9"),
        (RegisterX86::R10, "r10"),
        (RegisterX86::R11, "r11"),
        (RegisterX86::R12, "r12"),
        (RegisterX86::R13, "r13"),
        (RegisterX86::R14, "r14"),
        (RegisterX86::R15, "r15"),
    ];
    let x86 = [
        (RegisterX86::EAX, "eax"),
        (RegisterX86::ECX, "ecx"),
        (RegisterX86::EDX, "edx"),
        (RegisterX86::EBX, "ebx"),
        (RegisterX86::ESP, "esp"),
        (RegisterX86::EBP, "ebp"),
        (RegisterX86::ESI, "esi"),
        (RegisterX86::EDI, "edi"),
    ];
    if wide {
        registers.get(index as usize).copied()
    } else {
        x86.get(index as usize).copied()
    }
}

fn decode_control_read(
    bytes: &[u8],
    architecture: Architecture,
) -> Option<(u8, RegisterX86, &'static str)> {
    let mut at = 0;
    while at < bytes.len()
        && (matches!(
            bytes[at],
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf2 | 0xf3
        ) || architecture == Architecture::X64 && (0x40..=0x4f).contains(&bytes[at]))
    {
        at += 1;
    }
    if at + 3 != bytes.len() || bytes[at..at + 2] != [0x0f, 0x20] {
        return None;
    }
    let rex = if at != 0 && (0x40..=0x4f).contains(&bytes[at - 1]) {
        bytes[at - 1]
    } else {
        0
    };
    let modrm = bytes[at + 2];
    let cr = ((modrm >> 3) & 7) | ((rex & 4) << 1);
    let destination = (modrm & 7) | ((rex & 1) << 3);
    let (register, name) = register(architecture, destination)?;
    Some((cr, register, name))
}

fn arm(engine: &mut Unicorn<Trace>, pc: u64, size: u32, spec: ArmSpec) {
    let context = context(engine);
    let count = engine.get_data().instructions;
    let state = &mut engine.get_data_mut().cpu.native_reads;
    if state.attempts.len() == LIMIT {
        state.omitted_attempts = state.omitted_attempts.saturating_add(1);
        return;
    }
    let next_pc = pc.checked_add(size as u64);
    let row = state.attempts.len();
    state.attempts.push(ReadAttempt {
        pc,
        size,
        kind: spec.kind,
        control_register: spec.control_register,
        msr_index: spec.msr_index,
        instruction_count: count,
        architecture: context.architecture,
        thread_id: context.thread_id,
        current_thread: context.current_thread,
        processor: context.processor,
        execution_domain: context.execution_domain,
        destination: spec.destination_name,
        backend: spec.backend,
        completion: "pending_next_instruction",
        observed_value: None,
        observation_error: None,
    });
    if let Some(next_pc) = next_pc {
        state.pending = Some(Pending {
            row,
            next_pc,
            context,
            destination: spec.destination,
        });
    } else {
        state.attempts[row].completion = "address_overflow";
        state.observation_failures = state.observation_failures.saturating_add(1);
    }
}

pub(crate) fn arm_control(engine: &mut Unicorn<Trace>, pc: u64, size: u32) {
    let mut bytes = [0; 15];
    if !(1..=15).contains(&size) || engine.mem_read(pc, &mut bytes[..size as usize]).is_err() {
        engine.get_data_mut().cpu.native_reads.observation_failures += 1;
        return;
    }
    let Some((control, destination, name)) =
        decode_control_read(&bytes[..size as usize], engine.get_data().architecture)
    else {
        engine.get_data_mut().cpu.native_reads.observation_failures += 1;
        return;
    };
    if control == 8 {
        return;
    } // The existing CR8 model has its own receipt and semantics.
    arm(
        engine,
        pc,
        size,
        ArmSpec {
            kind: "control_register",
            control_register: Some(control),
            msr_index: None,
            destination: Destination::Control(destination),
            destination_name: name,
            backend: "native_control_register_passthrough",
        },
    );
}

pub(crate) fn arm_msr(engine: &mut Unicorn<Trace>, pc: u64, size: u32, index: u32) {
    let backend = if matches!(index, 0x174..=0x176 | 0xc0000080..=0xc0000084 | 0xc0000100..=0xc0000103)
    {
        "native_backend_tracked_family_result_unverified"
    } else {
        "native_backend_unmodeled_index_default_unverified"
    };
    arm(
        engine,
        pc,
        size,
        ArmSpec {
            kind: "msr",
            control_register: None,
            msr_index: Some(index),
            destination: Destination::Msr,
            destination_name: "edx:eax",
            backend,
        },
    );
}

pub(crate) fn before_instruction(engine: &mut Unicorn<Trace>, pc: u64) {
    let pending = engine.get_data_mut().cpu.native_reads.pending.take();
    let Some(pending) = pending else {
        return;
    };
    let current = context(engine);
    let completion = if current != pending.context {
        "context_changed"
    } else if pc != pending.next_pc {
        "nonfallthrough_next_instruction"
    } else {
        "observed_next_instruction"
    };
    let result = if completion == "observed_next_instruction" {
        match pending.destination {
            Destination::Control(register) => engine.reg_read(register),
            Destination::Msr => engine.reg_read(RegisterX86::EAX).and_then(|low| {
                engine
                    .reg_read(RegisterX86::EDX)
                    .map(|high| (low as u32 as u64) | ((high as u32 as u64) << 32))
            }),
        }
    } else {
        return finish(engine, pending.row, completion, None);
    };
    match result {
        Ok(value) => finish(engine, pending.row, completion, Some(value)),
        Err(error) => {
            let state = &mut engine.get_data_mut().cpu.native_reads;
            state.observation_failures = state.observation_failures.saturating_add(1);
            let row = &mut state.attempts[pending.row];
            row.completion = "diagnostic_register_read_failed";
            row.observation_error = Some(format!("{error:?}"));
        }
    }
}

fn finish(engine: &mut Unicorn<Trace>, index: usize, completion: &'static str, value: Option<u64>) {
    let row = &mut engine.get_data_mut().cpu.native_reads.attempts[index];
    row.completion = completion;
    row.observed_value = value;
}

pub(crate) fn report(engine: &Unicorn<Trace>, completion: &'static str) -> Option<Report> {
    let state = &engine.get_data().cpu.native_reads;
    if state.attempts.is_empty() && state.observation_failures == 0 && state.omitted_attempts == 0 {
        return None;
    }
    let mut attempts = state.attempts.clone();
    if let Some(pending) = &state.pending {
        let row = &mut attempts[pending.row];
        row.completion = "run_stopped_before_next_instruction";
        row.observation_error = Some(completion.to_owned());
    }
    Some(Report {
        attempts,
        limit: LIMIT,
        omitted_attempts: state.omitted_attempts,
        observation_failures: state.observation_failures,
        scope: "Passive admitted native non-CR8 MOV CR and non-TSC RDMSR attempts only; an instruction rejected by translation before the ordinary code hook has no receipt. Destination is sampled at the exact next fallthrough code hook in the same thread/processor/domain; incomplete rows never assert a consumed value. Raw instruction_count includes the current code-hook admission. Native backend values, especially unmodeled MSRs, are observations rather than Windows/hardware truth. No host MSR reads, guest mutation, broad register hook, or policy change.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::fixtures::counted_driver;

    fn driver(code: &[u8]) -> Vec<u8> {
        let mut bytes = counted_driver(Architecture::X64, 1);
        bytes[0x200..0x200 + code.len()].copy_from_slice(code);
        bytes
    }

    #[test]
    fn decoder_distinguishes_control_number_and_extended_destination() {
        assert_eq!(
            decode_control_read(&[0x0f, 0x20, 0xd0], Architecture::X64)
                .unwrap()
                .0,
            2
        );
        let (cr, register, name) =
            decode_control_read(&[0x2e, 0x41, 0x0f, 0x20, 0xd8], Architecture::X64).unwrap();
        assert_eq!((cr, register, name), (3, RegisterX86::R8, "r8"));
        assert!(decode_control_read(&[0x41, 0x0f, 0x20, 0xd8], Architecture::X86).is_none());
    }

    #[test]
    fn context_change_and_nonfallthrough_refuse_result_attribution() {
        let mut branch = crate::new_engine(Architecture::X64).unwrap();
        arm_msr(&mut branch, 0x1000, 2, 0xdeadbeef);
        before_instruction(&mut branch, 0x2000);
        let row = &report(&branch, "entry_return").unwrap().attempts[0];
        assert_eq!(row.completion, "nonfallthrough_next_instruction");
        assert_eq!(row.observed_value, None);
        assert!(!branch.get_data().cpu.native_reads.pending());
        drop(branch);

        let mut migrated = crate::new_engine(Architecture::X64).unwrap();
        arm_msr(&mut migrated, 0x1000, 2, 0xdeadbeef);
        migrated.get_data_mut().cpu.processor = 1;
        before_instruction(&mut migrated, 0x1002);
        let row = &report(&migrated, "entry_return").unwrap().attempts[0];
        assert_eq!(row.completion, "context_changed");
        assert_eq!(row.observed_value, None);
        assert!(!migrated.get_data().cpu.native_reads.pending());
    }

    #[test]
    fn generated_control_and_seeded_msr_values_need_exact_next_hook() {
        // MOV RAX,CR2; MOV R8,CR3; MOV RAX,R8; RET.
        let code = [
            0x0f, 0x20, 0xd0, 0x2e, 0x41, 0x0f, 0x20, 0xd8, 0x4c, 0x89, 0xc0, 0xc3,
        ];
        let result = crate::run_generated_image(&driver(&code), 100, 30_000_000).unwrap();
        assert_eq!(result.completion_reason, "entry_return", "{result:?}");
        let report = result.native_cpu_reads.unwrap();
        assert_eq!(report.attempts.len(), 2);
        assert_eq!(report.attempts[0].control_register, Some(2));
        assert_eq!(report.attempts[1].control_register, Some(3));
        assert_eq!(report.attempts[1].destination, "r8");
        assert!(
            report
                .attempts
                .iter()
                .all(|row| row.completion == "observed_next_instruction"
                    && row.observed_value.is_some()
                    && row.thread_id == 1
                    && row.execution_domain == "ordinary_thread")
        );
        assert_eq!(
            report.attempts[1].observed_value,
            Some(result.kernel_cpu.unwrap().initial.cr3)
        );

        // Guest WRMSR seeds LSTAR. RDMSR remains a native backend read, never a host MSR read.
        let mut msr = vec![0xb9];
        msr.extend_from_slice(&0xc0000082u32.to_le_bytes());
        msr.push(0xb8);
        msr.extend_from_slice(&0x12345678u32.to_le_bytes());
        msr.extend_from_slice(&[0x31, 0xd2, 0x0f, 0x30, 0x31, 0xc0, 0x0f, 0x32, 0xc3]);
        let result = crate::run_generated_image(&driver(&msr), 100, 30_000_000).unwrap();
        assert_eq!(result.completion_reason, "entry_return", "{result:?}");
        let report = result.native_cpu_reads.unwrap();
        assert_eq!(report.attempts.len(), 1);
        let row = &report.attempts[0];
        assert_eq!(row.msr_index, Some(0xc0000082));
        assert_eq!(row.observed_value, Some(0x12345678));
        assert_eq!(row.destination, "edx:eax");
        assert_eq!(row.completion, "observed_next_instruction");
    }

    #[test]
    fn pending_budget_and_cap_never_invent_a_result() {
        let single = driver(&[0x0f, 0x20, 0xd8, 0xc3]); // MOV RAX,CR3
        let stopped = crate::run_generated_image(&single, 1, 30_000_000).unwrap();
        let pending = &stopped.native_cpu_reads.unwrap().attempts[0];
        assert_eq!(pending.completion, "run_stopped_before_next_instruction");
        assert_eq!(pending.observed_value, None);

        let loop_code = [
            0xb9, 0x04, 0x01, 0, 0, 0x0f, 0x20, 0xd8, 0xff, 0xc9, 0x75, 0xf9, 0xc3,
        ];
        let repeated = crate::run_generated_image(&driver(&loop_code), 1000, 30_000_000).unwrap();
        assert_eq!(repeated.completion_reason, "entry_return", "{repeated:?}");
        let report = repeated.native_cpu_reads.unwrap();
        assert_eq!(report.attempts.len(), LIMIT);
        assert_eq!(report.omitted_attempts, 4);
        assert_eq!(
            report.attempts.last().unwrap().completion,
            "observed_next_instruction"
        );

        // A reserved CR read is rejected by the backend before our ordinary
        // code hook admits it, so the observer cannot invent an attempt.
        let invalid =
            crate::run_generated_image(&driver(&[0x0f, 0x20, 0xc8, 0xc3]), 100, 30_000_000)
                .unwrap();
        assert_eq!(invalid.completion_reason, "error");
        assert!(invalid.native_cpu_reads.is_none());

        // A backend-default MSR index is explicitly marked unmodeled, even if
        // this Unicorn build happens to return a scalar at the next hook.
        let mut unknown = vec![0xb9];
        unknown.extend_from_slice(&0xdeadbeefu32.to_le_bytes());
        unknown.extend_from_slice(&[0x0f, 0x32, 0xc3]);
        let unknown = crate::run_generated_image(&driver(&unknown), 100, 30_000_000).unwrap();
        let row = &unknown.native_cpu_reads.unwrap().attempts[0];
        assert_eq!(row.msr_index, Some(0xdeadbeef));
        assert_eq!(
            row.backend,
            "native_backend_unmodeled_index_default_unverified"
        );
    }
}
