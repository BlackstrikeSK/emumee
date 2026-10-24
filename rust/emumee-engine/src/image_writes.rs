//! Passive bounded write-attempt coverage for initially writable root mappings.
use super::*;
use crate::kernel_stack_writes::Writer;

const BYTE_LIMIT: u64 = 4 * 1024 * 1024;
const REGION_LIMIT: usize = 32;
const RECORD_LIMIT: usize = 4096;

#[derive(Clone, Debug, Serialize)]
pub struct Region {
    pub base: u64,
    pub size: u64,
    /// Bit n marks an observed write attempt overlapping guest byte base+n.
    pub touched_byte_bitmap: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub image_base: u64,
    pub image_size: u64,
    pub installed_instruction_count: u64,
    pub byte_limit: u64,
    pub record_limit: usize,
    pub watched_regions: Vec<Region>,
    pub omitted_regions: Vec<(u64, u64)>,
    pub native_overlapping_attempts: u64,
    pub model_overlapping_writes: u64,
    pub observations_omitted: u64,
    pub observations: Vec<Writer>,
    pub scope: &'static str,
}

pub(crate) struct State {
    base: u64,
    size: u64,
    installed: u64,
    regions: Vec<Region>,
    omitted: Vec<(u64, u64)>,
    sequence: u64,
    native: u64,
    model: u64,
    records: Vec<Writer>,
}

impl State {
    fn overlaps(&self, address: u64, size: usize) -> bool {
        size != 0
            && self.regions.iter().any(|region| {
                address < region.base + region.size
                    && address.saturating_add(size as u64) > region.base
            })
    }

    fn record(&mut self, mut writer: Writer) {
        self.sequence = self.sequence.saturating_add(1);
        writer.sequence = self.sequence;
        if writer.source == "native_prewrite_attempt" {
            self.native = self.native.saturating_add(1);
        } else {
            self.model = self.model.saturating_add(1);
        }
        for region in &mut self.regions {
            let first = writer.write_address.max(region.base);
            let end = writer
                .write_address
                .saturating_add(writer.write_size as u64)
                .min(region.base + region.size);
            if first >= end {
                continue;
            }
            let first = (first - region.base) as usize;
            let end = (end - region.base) as usize;
            let first_full = first.div_ceil(8).min(end / 8);
            let last_full = end / 8;
            region.touched_byte_bitmap[first_full..last_full].fill(0xff);
            for byte in first..end.min(first_full * 8) {
                region.touched_byte_bitmap[byte / 8] |= 1 << (byte % 8);
            }
            for byte in (last_full * 8).max(first)..end {
                region.touched_byte_bitmap[byte / 8] |= 1 << (byte % 8);
            }
        }
        let index = ((self.sequence - 1) % RECORD_LIMIT as u64) as usize;
        if self.records.len() < RECORD_LIMIT {
            self.records.push(writer);
        } else {
            self.records[index] = writer;
        }
    }
}

fn observe(engine: &mut Unicorn<Trace>, address: u64, size: usize, source: &'static str) {
    if !engine
        .get_data()
        .image_writes
        .as_ref()
        .is_some_and(|state| state.overlaps(address, size))
    {
        return;
    }
    let trace = engine.get_data();
    let writer = Writer {
        sequence: 0,
        source,
        pc: if source == "native_prewrite_attempt" {
            (trace.instructions != 0)
                .then(|| trace.entries[((trace.instructions - 1) as usize) & (TAIL - 1)].pc)
        } else {
            engine.pc_read().ok()
        },
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
    engine
        .get_data_mut()
        .image_writes
        .as_mut()
        .unwrap()
        .record(writer);
}

pub(crate) fn install(engine: &mut Unicorn<Trace>, base: u64, size: u64) -> Result<()> {
    ensure!(
        size != 0,
        "Image write observation requires a nonempty image"
    );
    let end = base
        .checked_add(size)
        .context("Image write observation overflow")?;
    ensure!(
        engine.get_data().image_writes.is_none(),
        "Image write observer already installed"
    );
    let mut selected = 0u64;
    let mut regions = Vec::new();
    let mut omitted = Vec::new();
    for region in engine.get_data().apis.memory.regions().filter(|region| {
        region.base >= base && region.base < end && region.permissions.contains(Permissions::WRITE)
    }) {
        ensure!(
            region.base + region.size <= end,
            "Image write region crosses image boundary"
        );
        if regions.len() >= REGION_LIMIT || selected + region.size > BYTE_LIMIT {
            omitted.push((region.base, region.size));
            continue;
        }
        selected += region.size;
        regions.push(Region {
            base: region.base,
            size: region.size,
            touched_byte_bitmap: vec![0; (region.size as usize).div_ceil(8)],
        });
    }
    engine.get_data_mut().image_writes = Some(State {
        base,
        size,
        installed: engine.get_data().instructions,
        regions,
        omitted,
        sequence: 0,
        native: 0,
        model: 0,
        records: Vec::new(),
    });
    uc(engine.add_mem_hook(
        HookType::MEM_WRITE,
        base,
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

pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = engine.get_data().image_writes.as_ref()?;
    let mut observations = state.records.clone();
    observations.sort_by_key(|record| record.sequence);
    Some(Report {
        image_base: state.base,
        image_size: state.size,
        installed_instruction_count: state.installed,
        byte_limit: BYTE_LIMIT,
        record_limit: RECORD_LIMIT,
        watched_regions: state.regions.clone(),
        omitted_regions: state.omitted.clone(),
        native_overlapping_attempts: state.native,
        model_overlapping_writes: state.model,
        observations_omitted: state.sequence.saturating_sub(observations.len() as u64),
        observations,
        scope: "Passive initially writable submitted-root-image coverage installed after loader/import setup and before guest entry. Bitmap bit n (least significant bit first within each byte) records any observed native pre-write attempt or cpu::write model result overlapping guest byte base+n; bits persist after the most recent4096 event ring evicts old records. Native records are attempts, not retired stores or committed byte values. Model success precedes cache invalidation; failure may have partial effects. Native hook covers write start addresses inside the original root image only; starts outside it, later writable permission/remap changes, aliases and direct host writes outside cpu::write are not covered. Omitted region geometry and event counts are explicit. No guest reads, branch/value/policy/time changes, initialization, ownership, rejection or unpacking inference.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_write_bitmap_preserves_early_model_write_after_event_eviction() {
        let mut engine = new_engine(Architecture::X64).unwrap();
        let base = 0x1000_0000;
        engine
            .mem_map(base, 4096, Prot::READ | Prot::WRITE)
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(base, 4096, Permissions::RW, None, "generated image data")
            .unwrap();
        install(&mut engine, base, 4096).unwrap();
        crate::cpu::write(&mut engine, base + 7, &[0xa5; 10]).unwrap();
        for _ in 0..RECORD_LIMIT {
            crate::cpu::write(&mut engine, base + 100, &[0x5a]).unwrap();
        }
        let report = report(&engine).unwrap();
        assert_eq!(report.observations.len(), RECORD_LIMIT);
        assert_eq!(report.observations_omitted, 1);
        assert_eq!(report.native_overlapping_attempts, 0);
        assert_eq!(report.model_overlapping_writes, RECORD_LIMIT as u64 + 1);
        let bitmap = &report.watched_regions[0].touched_byte_bitmap;
        assert_eq!(&bitmap[..3], &[0x80, 0xff, 0x01]);
        assert_eq!(bitmap[100 / 8], 1 << (100 % 8));
        assert_eq!(report.observations[0].sequence, 2);
        assert_eq!(
            report.observations.last().unwrap().sequence,
            RECORD_LIMIT as u64 + 1
        );
        assert!(
            report
                .observations
                .iter()
                .all(|event| event.write_address == base + 100)
        );
    }
}
