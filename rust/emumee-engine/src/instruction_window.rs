//! Opt-in counter-range instruction snapshots and common model-write receipts.
//! Observation never changes guest execution, values, policy or fault state.
use super::*;
use emumee_core::driver_input::InstructionWindow;

const MAX_ROWS: u32 = 65_536;
const WRITE_LIMIT: usize = 4096;
const WRITE_PREFIX: usize = 256;
const CONTEXT_LIMIT: usize = 256;
const POINTER_SAMPLE_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Context {
    pub thread_id: u64,
    pub current_thread: u64,
    pub processor: u32,
    pub execution_domain: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct Instruction {
    pub sequence: u64,
    pub pc: u64,
    pub size: u32,
    pub instruction_ordinal: u64,
    pub phase: &'static str,
    pub instruction_bytes: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_registers: Option<Vec<u64>>,
    pub register_deltas: Vec<(u8, u64)>,
    pub context_id: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct ModelWrite {
    pub sequence: u64,
    pub raw_instruction_count: u64,
    pub pc: Option<u64>,
    pub address: u64,
    pub requested_bytes: usize,
    pub requested_prefix: Vec<u8>,
    pub prefix_truncated: bool,
    pub succeeded: bool,
    pub effect: &'static str,
    pub thread_id: u64,
    pub current_thread: u64,
    pub processor: u32,
    pub execution_domain: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct Stop {
    pub reason: &'static str,
    pub raw_instruction_count: u64,
    pub pc: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StackWriterRange {
    pub address: u64,
    pub size: usize,
    pub writer: kernel_stack_writes::Writer,
}

#[derive(Clone, Debug, Serialize)]
pub struct StackWritesCheckpoint {
    pub observation_raw_instruction_count: u64,
    pub observation_phase: &'static str,
    pub stack_base: u64,
    pub stack_size: u64,
    pub watched_page: u64,
    pub native_hook_start: u64,
    pub native_hook_end_inclusive: u64,
    pub frozen_before_first_callback: bool,
    pub freeze_instruction_count: Option<u64>,
    pub native_overlapping_attempts: u64,
    pub model_overlapping_writes: u64,
    pub observed_bytes: usize,
    pub last_observed_ranges: Vec<StackWriterRange>,
    pub scope: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct PointerSample {
    pub register: &'static str,
    pub address: u64,
    pub bytes: Vec<u8>,
}

impl StackWritesCheckpoint {
    fn at_first_row(report: kernel_stack_writes::Report, ordinal: u64, api_gate: bool) -> Self {
        Self {
            observation_raw_instruction_count: ordinal,
            observation_phase: if api_gate {
                "api_post_dispatch_pre_RET"
            } else {
                "native_pre_instruction"
            },
            stack_base: report.stack_base,
            stack_size: report.stack_size,
            watched_page: report.watched_page,
            native_hook_start: report.native_hook_start,
            native_hook_end_inclusive: report.native_hook_end_inclusive,
            frozen_before_first_callback: report.frozen_before_first_callback,
            freeze_instruction_count: report.freeze_instruction_count,
            native_overlapping_attempts: report.native_overlapping_attempts,
            model_overlapping_writes: report.model_overlapping_writes,
            observed_bytes: report.observed_bytes,
            last_observed_ranges: report
                .last_observed_ranges
                .into_iter()
                .map(|range| StackWriterRange {
                    address: range.address,
                    size: range.size,
                    writer: range.writer,
                })
                .collect(),
            scope: "One-time copy of the passive owned root-stack writer table at the first successfully captured instruction row. Native writers are pre-write attempts, not retired stores or byte values. A post-dispatch API row may already include modeled API writes at the same raw count. The final kernel_stack_writes report remains independently active and may reflect later writes or callback freeze.",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub architecture: Architecture,
    pub start_instruction: u64,
    pub end_instruction_exclusive: u64,
    pub max_records: u32,
    pub register_order: Vec<&'static str>,
    pub contexts: Vec<Context>,
    pub context_limit: usize,
    pub instructions: Vec<Instruction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_stack_writes: Option<StackWritesCheckpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_row_pointer_samples: Option<Vec<PointerSample>>,
    pub status: &'static str,
    pub truncated: bool,
    pub stop: Stop,
    pub run_completion: &'static str,
    pub model_write_calls: u64,
    pub model_writes: Vec<ModelWrite>,
    pub model_write_record_limit: usize,
    pub model_write_prefix_limit: usize,
    pub model_write_records_omitted: u64,
    pub model_write_bytes_omitted: u64,
    pub model_write_pc_failures: u64,
    pub scope: &'static str,
}

pub(crate) struct State {
    config: InstructionWindow,
    end: u64,
    instructions: Vec<Instruction>,
    first_row_checked_stack_writes: bool,
    initial_stack_writes: Option<StackWritesCheckpoint>,
    first_row_pointer_samples: Option<Vec<PointerSample>>,
    previous_registers: Option<Vec<u64>>,
    contexts: Vec<Context>,
    model_writes: Vec<ModelWrite>,
    model_write_calls: u64,
    model_write_records_omitted: u64,
    model_write_bytes_omitted: u64,
    model_write_pc_failures: u64,
    sequence: u64,
    stop: Option<Stop>,
}

impl State {
    pub(crate) fn new(config: InstructionWindow) -> Self {
        let end = config
            .start_instruction
            .checked_add(u64::from(config.max_records));
        let invalid = config.max_records == 0 || config.max_records > MAX_ROWS || end.is_none();
        Self {
            end: end.unwrap_or(config.start_instruction),
            stop: invalid.then(|| Stop {
                reason: "invalid_configuration",
                raw_instruction_count: 0,
                pc: None,
                error: Some(
                    "Instruction window requires1..65536 records and a nonoverflowing range".into(),
                ),
            }),
            config,
            instructions: Vec::new(),
            first_row_checked_stack_writes: false,
            initial_stack_writes: None,
            first_row_pointer_samples: None,
            previous_registers: None,
            contexts: Vec::new(),
            model_writes: Vec::new(),
            model_write_calls: 0,
            model_write_records_omitted: 0,
            model_write_bytes_omitted: 0,
            model_write_pc_failures: 0,
            sequence: 0,
        }
    }

    #[inline]
    pub(crate) fn interested(&self, ordinal: u64) -> bool {
        self.stop.is_none() && self.config.start_instruction <= ordinal && ordinal < self.end
    }

    fn next_sequence(&mut self) -> u64 {
        self.sequence = self.sequence.saturating_add(1);
        self.sequence
    }
}

fn context(engine: &Unicorn<Trace>) -> (u64, u64, u32, &'static str) {
    let ipi = crate::ipi::member_running(engine);
    (
        if ipi {
            0
        } else {
            crate::threads::current_id(engine)
        },
        crate::threads::thread_address(engine),
        engine.get_data().cpu.processor,
        if ipi {
            "ipi_member"
        } else if crate::threads::dpc::active(engine) {
            "dpc"
        } else {
            "ordinary_thread"
        },
    )
}

fn stop(engine: &mut Unicorn<Trace>, pc: u64, reason: &'static str, error: String) {
    let ordinal = engine.get_data().instructions;
    if let Some(window) = engine.get_data_mut().instruction_window.as_mut() {
        window.stop = Some(Stop {
            reason,
            raw_instruction_count: ordinal,
            pc: Some(pc),
            error: Some(error),
        });
    }
}

pub(crate) fn before_instruction(engine: &mut Unicorn<Trace>, pc: u64, size: u32, api_gate: bool) {
    let ordinal = engine.get_data().instructions;
    if !engine
        .get_data()
        .instruction_window
        .as_ref()
        .is_some_and(|window| window.interested(ordinal))
    {
        return;
    }
    if !(1..=15).contains(&size) {
        stop(
            engine,
            pc,
            "invalid_instruction_size",
            format!("Diagnostic instruction size{size} outside1..15"),
        );
        return;
    }
    let registers =
        match api::kernel_prompt::register_values(engine.get_data().architecture, |register| {
            engine.reg_read(register)
        }) {
            Ok(registers) => registers,
            Err(error) => {
                stop(engine, pc, "register_read_failed", error);
                return;
            }
        };
    let mut bytes = vec![0; size as usize];
    if let Err(error) = engine.mem_read(pc, &mut bytes) {
        stop(
            engine,
            pc,
            "instruction_bytes_read_failed",
            format!("Diagnostic instruction byte read: {error:?}"),
        );
        return;
    }
    let (thread_id, current_thread, processor, execution_domain) = context(engine);
    let current_context = Context {
        thread_id,
        current_thread,
        processor,
        execution_domain,
    };
    let existing_context = engine
        .get_data()
        .instruction_window
        .as_ref()
        .unwrap()
        .contexts
        .iter()
        .position(|previous| previous == &current_context);
    if existing_context.is_none()
        && engine
            .get_data()
            .instruction_window
            .as_ref()
            .unwrap()
            .contexts
            .len()
            >= CONTEXT_LIMIT
    {
        stop(
            engine,
            pc,
            "context_limit",
            "Diagnostic unique context table reached256 entries".into(),
        );
        return;
    }
    let checkpoint = (!engine
        .get_data()
        .instruction_window
        .as_ref()
        .unwrap()
        .first_row_checked_stack_writes)
        .then(|| kernel_stack_writes::report(engine))
        .flatten()
        .map(|report| StackWritesCheckpoint::at_first_row(report, ordinal, api_gate));
    let pointer_samples = (!engine
        .get_data()
        .instruction_window
        .as_ref()
        .unwrap()
        .first_row_checked_stack_writes)
        .then(|| {
            api::kernel_prompt::register_spec(engine.get_data().architecture)
                .iter()
                .zip(&registers)
                .filter_map(|((_, name), address)| {
                    if *name == "eflags" {
                        return None;
                    }
                    let mut bytes = vec![0; POINTER_SAMPLE_BYTES];
                    engine.mem_read(*address, &mut bytes).ok()?;
                    Some(PointerSample {
                        register: name,
                        address: *address,
                        bytes,
                    })
                })
                .collect::<Vec<_>>()
        });
    let window = engine.get_data_mut().instruction_window.as_mut().unwrap();
    if !window.first_row_checked_stack_writes {
        window.first_row_checked_stack_writes = true;
        window.initial_stack_writes = checkpoint;
        window.first_row_pointer_samples = pointer_samples;
    }
    let context_id = existing_context.unwrap_or_else(|| {
        let index = window.contexts.len();
        window.contexts.push(current_context);
        index
    }) as u16;
    let full_registers = window
        .previous_registers
        .is_none()
        .then(|| registers.clone());
    let register_deltas = window
        .previous_registers
        .as_ref()
        .map_or_else(Vec::new, |previous| {
            registers
                .iter()
                .zip(previous)
                .enumerate()
                .filter_map(|(index, (value, old))| (value != old).then_some((index as u8, *value)))
                .collect()
        });
    let sequence = window.next_sequence();
    window.instructions.push(Instruction {
        sequence,
        pc,
        size,
        instruction_ordinal: ordinal,
        phase: if api_gate {
            "api_post_dispatch_pre_RET"
        } else {
            "native_pre_instruction"
        },
        instruction_bytes: bytes,
        full_registers,
        register_deltas,
        context_id,
    });
    window.previous_registers = Some(registers);
    if window.instructions.len() >= window.config.max_records as usize {
        window.stop = Some(Stop {
            reason: "record_limit",
            raw_instruction_count: ordinal,
            pc: Some(pc),
            error: None,
        });
    }
}

pub(crate) fn model_write(
    engine: &mut Unicorn<Trace>,
    address: u64,
    bytes: &[u8],
    succeeded: bool,
) {
    let ordinal = engine.get_data().instructions;
    if bytes.is_empty()
        || !engine
            .get_data()
            .instruction_window
            .as_ref()
            .is_some_and(|window| window.interested(ordinal))
    {
        return;
    }
    let window = engine.get_data_mut().instruction_window.as_mut().unwrap();
    window.model_write_calls = window.model_write_calls.saturating_add(1);
    let sequence = window.next_sequence();
    if window.model_writes.len() >= WRITE_LIMIT {
        window.model_write_records_omitted = window.model_write_records_omitted.saturating_add(1);
        window.model_write_bytes_omitted = window
            .model_write_bytes_omitted
            .saturating_add(bytes.len() as u64);
        return;
    }
    let pc = engine.pc_read().ok();
    let (thread_id, current_thread, processor, execution_domain) = context(engine);
    let window = engine.get_data_mut().instruction_window.as_mut().unwrap();
    window.model_write_pc_failures += u64::from(pc.is_none());
    let kept = bytes.len().min(WRITE_PREFIX);
    window.model_write_bytes_omitted = window
        .model_write_bytes_omitted
        .saturating_add((bytes.len() - kept) as u64);
    window.model_writes.push(ModelWrite {
        sequence,
        raw_instruction_count: ordinal,
        pc,
        address,
        requested_bytes: bytes.len(),
        requested_prefix: bytes[..kept].to_vec(),
        prefix_truncated: kept != bytes.len(),
        succeeded,
        effect: if succeeded {
            "backend_mem_write_succeeded_cache_invalidation_pending"
        } else {
            "backend_mem_write_failed_partial_effects_unknown"
        },
        thread_id,
        current_thread,
        processor,
        execution_domain,
    });
}

pub(crate) fn report(engine: &Unicorn<Trace>, completion: &'static str) -> Option<Report> {
    let trace = engine.get_data();
    let state = trace.instruction_window.as_ref()?;
    let status = if let Some(stop) = &state.stop {
        if stop.reason == "record_limit" {
            "record_limit"
        } else {
            "diagnostic_failure"
        }
    } else if state.instructions.is_empty() && state.model_write_calls == 0 {
        "not_reached"
    } else {
        "prefix"
    };
    Some(Report {
        architecture: trace.architecture,
        start_instruction: state.config.start_instruction,
        end_instruction_exclusive: state.end,
        max_records: state.config.max_records,
        register_order: api::kernel_prompt::register_spec(trace.architecture)
            .iter()
            .map(|(_, name)| *name)
            .collect(),
        contexts: state.contexts.clone(),
        context_limit: CONTEXT_LIMIT,
        instructions: state.instructions.clone(),
        initial_stack_writes: state.initial_stack_writes.clone(),
        first_row_pointer_samples: state.first_row_pointer_samples.clone(),
        status,
        truncated: status != "record_limit",
        stop: state.stop.clone().unwrap_or(Stop {
            reason: if status == "not_reached" {
                "not_reached"
            } else {
                "run_stopped"
            },
            raw_instruction_count: trace.instructions,
            pc: None,
            error: None,
        }),
        run_completion: completion,
        model_write_calls: state.model_write_calls,
        model_writes: state.model_writes.clone(),
        model_write_record_limit: WRITE_LIMIT,
        model_write_prefix_limit: WRITE_PREFIX,
        model_write_records_omitted: state.model_write_records_omitted,
        model_write_bytes_omitted: state.model_write_bytes_omitted,
        model_write_pc_failures: state.model_write_pc_failures,
        scope: "Opt-in global pre-admission count range [start,end), maximum65536 rows, observed inside the existing admission hook. Native rows are pre-instruction; API rows are explicitly after modeled dispatch and before the admitted synthetic RET, not pre-call arguments. Exact instruction bytes are read at observation time; GPR/EFLAGS use the fixed architecture order, first full vector then indexed deltas against the previous stored row even across context changes. Actual thread/processor/domain is stored in a maximum256-entry context table; row context_id is its zero-based index. A new context beyond the bound stops only observation. The first successful row also samples at most64 bytes at each readable general-purpose register address; failed diagnostic reads are omitted and samples do not assert guest access or ownership. The optional owned root-stack writer checkpoint is copied once at the first successfully captured instruction row; it does not freeze or replace the final writer observer. Native writer records are attempts, not retired stores or byte values. Common cpu::write result receipts use the raw counter at write time (not an inferred native ordinal), chronological sequence, and at most4096 records/256 requested-prefix bytes each. Setup writes can precede the first native snapshot when start=0. Success precedes cache invalidation; a failed write can have partial unknown effects. Prefix bytes are exact requested bytes, not readback or proof of bytes committed. Omitted records/bytes are counted; outside-range/native/direct-host writes and interval-edge effects are not claimed complete. Diagnostic register/byte failures stop only observation; no guest fault, register/value/policy/time/branch or execution change is introduced. No causal predicate, initialization or unpacking claim.",
    })
}
