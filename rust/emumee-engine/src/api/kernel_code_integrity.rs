//! Documented class103 over explicit immutable machine configuration.
//! A returned option mask reports configured state; it is not an attestation.
use super::*;
use emumee_core::kernel_code_integrity as contract;
#[derive(Default)]
pub(crate) struct State {
    events: Vec<Event>,
    omitted: u64,
    native_effect_failure: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub instruction_ordinal: u64,
    pub capacity: u32,
    pub declared_length: Option<u32>,
    pub required: u32,
    pub status: u32,
    pub copied: u32,
    pub options: Option<u32>,
    pub return_length_written: bool,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub events: Vec<Event>,
    pub events_omitted: u64,
    pub native_effect_failure: bool,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let s = &engine.get_data().apis.kernel_code_integrity;
    if s.events.is_empty() && !s.native_effect_failure {
        return None;
    }
    Some(Report {
        events: s.events.clone(),
        events_omitted: s.omitted,
        native_effect_failure: s.native_effect_failure,
        scope: "SystemCodeIntegrityInformation103: exact8-byte buffer and caller Length8, DWORD option mask from explicit boot_config.code_integrity_options, optional ULONG ReturnLength8. Reports configured options only; no signature validation, enforcement, trust, HVCI implementation or boot-success attestation. RW caller-owned buffers only; output aliases unsupported. Other information classes remain separately bounded.",
    })
}
fn writeable(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    require(engine, address, size, P::WRITE)?;
    super::mdl::require_api_write(engine, address, size)
}
fn overlaps(a: u64, n: u64, b: u64, m: u64) -> bool {
    n != 0 && m != 0 && a < b.saturating_add(m) && b < a.saturating_add(n)
}
pub(super) fn query(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().apis.kernel_mode && uc(engine.reg_read(RegisterX86::CS))? & 3 == 0,
        "Code integrity query requires a CPL0 kernel context"
    );
    ensure!(
        !engine
            .get_data()
            .apis
            .kernel_code_integrity
            .native_effect_failure,
        "Code integrity native effect failed; execution cannot resume"
    );
    let capacity = args[2] as u32;
    if args[3] != 0 {
        writeable(engine, args[3], 4)?;
    }
    let declared = if capacity == contract::SIZE {
        require(engine, args[1], 4, P::READ)?;
        Some(u32::from_le_bytes(
            uc(engine.mem_read_as_vec(args[1], 4))?.try_into().unwrap(),
        ))
    } else {
        None
    };
    let planned = contract::plan(
        capacity,
        declared.unwrap_or(0),
        engine.get_data().machine.code_integrity_options(),
    )?;
    if planned.bytes.is_some() {
        require(engine, args[1], 8, P::READ)?;
        writeable(engine, args[1], 8)?;
        ensure!(
            args[3] == 0 || !overlaps(args[1], 8, args[3], 4),
            "Code integrity query output aliases are unsupported"
        );
    }
    let needed = planned.required.to_le_bytes();
    let mut writes: Vec<(u64, &[u8])> = Vec::new();
    if let Some(bytes) = planned.bytes.as_ref() {
        writes.push((args[1], bytes));
    }
    if args[3] != 0 {
        writes.push((args[3], &needed));
    }
    for (address, bytes) in writes {
        if let Err(error) = crate::cpu::write(engine, address, bytes) {
            engine
                .get_data_mut()
                .apis
                .kernel_code_integrity
                .native_effect_failure = true;
            return Err(error);
        }
    }
    let event = Event {
        instruction_ordinal: engine.get_data().instructions,
        capacity,
        declared_length: declared,
        required: planned.required,
        status: planned.status,
        copied: if planned.bytes.is_some() { 8 } else { 0 },
        options: planned
            .bytes
            .map(|b| u32::from_le_bytes(b[4..].try_into().unwrap())),
        return_length_written: args[3] != 0,
    };
    let s = &mut engine.get_data_mut().apis.kernel_code_integrity;
    if s.events.len() < 128 {
        s.events.push(event);
    } else {
        s.omitted = s.omitted.saturating_add(1);
    }
    Ok(planned.status.into())
}
