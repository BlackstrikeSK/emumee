//! Bounded last-observed writers to the final page of the owned entry stack.
//! Native callbacks are pre-write attempts, never retirement or value evidence.
use super::*;

const PAGE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Writer {
    pub sequence: u64,
    pub source: &'static str,
    pub pc: Option<u64>,
    pub raw_instruction_count: u64,
    pub write_address: u64,
    pub write_size: usize,
    pub thread_id: u64,
    pub current_thread: u64,
    pub processor: u32,
    pub execution_domain: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Range {
    pub address: u64,
    pub size: usize,
    pub writer: Writer,
}

#[derive(Debug, Serialize)]
pub struct Report {
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
    pub last_observed_ranges: Vec<Range>,
    pub scope: &'static str,
}

pub(crate) struct State {
    stack: u64,
    size: u64,
    page: u64,
    writers: Vec<Option<Writer>>,
    sequence: u64,
    native_attempts: u64,
    model_writes: u64,
    freeze: Option<u64>,
}

impl State {
    fn overlap(&self, address: u64, size: usize) -> Option<(usize, usize)> {
        if self.freeze.is_some() || size == 0 {
            return None;
        }
        let first = address.max(self.page);
        let end = address
            .saturating_add(size as u64)
            .min(self.page + PAGE as u64);
        if first >= end {
            return None;
        }
        Some(((first - self.page) as usize, (end - self.page) as usize))
    }

    fn record(&mut self, mut writer: Writer, first: usize, end: usize) {
        self.sequence = self.sequence.saturating_add(1);
        writer.sequence = self.sequence;
        if writer.source == "native_prewrite_attempt" {
            self.native_attempts = self.native_attempts.saturating_add(1);
        } else {
            self.model_writes = self.model_writes.saturating_add(1);
        }
        self.writers[first..end].fill(Some(writer));
    }
}

fn observe(engine: &mut Unicorn<Trace>, address: u64, size: usize, source: &'static str) {
    let Some((first, end)) = engine
        .get_data()
        .kernel_stack_writes
        .as_ref()
        .and_then(|state| state.overlap(address, size))
    else {
        return;
    };
    let trace = engine.get_data();
    // Native writes follow instruction admission and can use the existing tail;
    // model writes may occur inside dispatch before that gate is counted.
    let pc = if source == "native_prewrite_attempt" {
        (trace.instructions != 0)
            .then(|| trace.entries[((trace.instructions - 1) as usize) & (TAIL - 1)].pc)
    } else {
        engine.pc_read().ok()
    };
    let writer = Writer {
        sequence: 0,
        source,
        pc,
        raw_instruction_count: trace.instructions,
        write_address: address,
        write_size: size,
        thread_id: if crate::ipi::member_running(engine) {
            0
        } else {
            crate::threads::current_id(engine)
        },
        current_thread: crate::threads::thread_address(engine),
        processor: trace.cpu.processor,
        execution_domain: if crate::ipi::member_running(engine) {
            "ipi_member"
        } else if crate::threads::dpc::active(engine) {
            "dpc"
        } else {
            "ordinary_thread"
        },
    };
    if let Some(state) = engine.get_data_mut().kernel_stack_writes.as_mut() {
        state.record(writer, first, end);
    }
}

pub(crate) fn install(engine: &mut Unicorn<Trace>, stack: u64, size: u64) -> Result<()> {
    if !engine.get_data().apis.kernel_mode {
        return Ok(());
    }
    ensure!(
        size >= PAGE as u64,
        "Owned stack observation requires a full page"
    );
    let end = stack
        .checked_add(size)
        .context("Owned stack observation overflow")?;
    engine.get_data_mut().kernel_stack_writes = Some(State {
        stack,
        size,
        page: end - PAGE as u64,
        writers: vec![None; PAGE],
        sequence: 0,
        native_attempts: 0,
        model_writes: 0,
        freeze: None,
    });
    // The entire owned stack is the hook's start-address range, so an ordinary
    // store starting below the final page and crossing into it is observed too.
    uc(engine.add_mem_hook(
        HookType::MEM_WRITE,
        stack,
        end - 1,
        |engine, _, address, size, _| {
            observe(engine, address, size, "native_prewrite_attempt");
            true
        },
    ))?;
    Ok(())
}

pub(crate) fn model_write(engine: &mut Unicorn<Trace>, address: u64, size: usize, succeeded: bool) {
    observe(
        engine,
        address,
        size,
        if succeeded {
            "model_mem_write_succeeded"
        } else {
            "model_mem_write_failed_partial_effects_unknown"
        },
    );
}

pub(crate) fn freeze_before_callback(engine: &mut Unicorn<Trace>) {
    let ordinal = engine.get_data().instructions;
    if let Some(state) = engine.get_data_mut().kernel_stack_writes.as_mut() {
        state.freeze.get_or_insert(ordinal);
    }
}

pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = engine.get_data().kernel_stack_writes.as_ref()?;
    let mut ranges: Vec<Range> = Vec::new();
    let mut observed = 0;
    for (offset, writer) in state.writers.iter().enumerate() {
        let Some(writer) = writer else { continue };
        observed += 1;
        let address = state.page + offset as u64;
        if let Some(last) = ranges.last_mut()
            && last.address + last.size as u64 == address
            && last.writer == *writer
        {
            last.size += 1;
        } else {
            ranges.push(Range {
                address,
                size: 1,
                writer: *writer,
            });
        }
    }
    Some(Report {
        stack_base: state.stack,
        stack_size: state.size,
        watched_page: state.page,
        native_hook_start: state.stack,
        native_hook_end_inclusive: state.stack + state.size - 1,
        frozen_before_first_callback: state.freeze.is_some(),
        freeze_instruction_count: state.freeze,
        native_overlapping_attempts: state.native_attempts,
        model_overlapping_writes: state.model_writes,
        observed_bytes: observed,
        last_observed_ranges: ranges,
        scope: "Passive fixed4096-slot last-observed writer table for the final owned root entry-stack page, installed before entry setup and frozen on the first admitted ExCreateCallback adapter call before its modeled effects. If that adapter is never reached, observations extend to run stop. Native records are pre-write attempts, not completed stores or retirement; their PC comes from the existing last admitted instruction tail and raw counter. Model records follow the existing mem_write result; failures may have partial unknown effects, success precedes cache invalidation. Identical writes still replace prior observations. No guest memory/value reads, CPU/time/policy changes or driver-specific targets. Native hooks cover write start addresses within the owned stack only; starts outside it, alias/remap effects and direct host writes outside cpu::write are not covered. Missing records do not prove unwritten/zero memory. Ranges describe observed provenance only, not byte values, causal predicates, initialization or unpacking.",
    })
}
