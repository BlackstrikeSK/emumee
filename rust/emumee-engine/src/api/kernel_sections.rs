//! Native section lookup against explicit closed object-directory inventories.
//! Found sections remain unsupported until owned lifetime/access/handle state
//! exists. Unknown directories are never treated as empty.
use super::*;
use emumee_core::kernel_namespace::SectionLookup;
pub(super) const ROUTINES: &[&str] = &["ZwOpenSection", "NtOpenSection"];

#[derive(Default)]
pub(crate) struct State {
    events: Vec<Event>,
    omitted: u64,
    native_effect_failure: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub instruction_ordinal: u64,
    pub name: String,
    pub desired_access: u32,
    pub attributes: u32,
    pub status: u32,
    pub output_cleared: bool,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub events: Vec<Event>,
    pub events_omitted: u64,
    pub native_effect_failure: bool,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().apis.kernel_sections;
    if state.events.is_empty() && !state.native_effect_failure {
        return None;
    }
    Some(Report {
        events: state.events.clone(),
        events_omitted: state.omitted,
        native_effect_failure: state.native_effect_failure,
        scope: "Nt/ZwOpenSection negative name/path/type lookups over explicitly configured closed ASCII object-directory snapshots. Clears the caller HANDLE on resolved failure. No host lookup, successful section handles, ACL decisions, relative/root-handle names, symbolic-link traversal, live device namespace, section creation, mapping or memory access is synthesized. Unconfigured or unobserved directories remain explicit unsupported boundaries.",
    })
}
fn pointer(bytes: &[u8], offset: usize, width: usize) -> u64 {
    let mut value = [0; 8];
    value[..width].copy_from_slice(&bytes[offset..offset + width]);
    u64::from_le_bytes(value)
}
pub(super) fn open(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().apis.kernel_mode && uc(engine.reg_read(RegisterX86::CS))? & 3 == 0,
        "Native section lookup requires a CPL0 kernel context"
    );
    ensure!(
        !engine.get_data().apis.kernel_sections.native_effect_failure,
        "Native section output failed; execution cannot resume"
    );
    ensure!(
        super::kernel_sync::observe_irql(engine)? == 0,
        "Native section lookup requires PASSIVE_LEVEL"
    );
    let width = engine.get_data().architecture.width();
    let size = if width == 8 { 48 } else { 24 };
    let raw = read(engine, args[2], size)?;
    ensure!(
        u32::from_le_bytes(raw[..4].try_into().unwrap()) == size as u32,
        "Native section OBJECT_ATTRIBUTES length unsupported"
    );
    let (root, name, flags, security, qos) = if width == 8 {
        (8, 16, 24, 32, 40)
    } else {
        (4, 8, 12, 16, 20)
    };
    let attributes = u32::from_le_bytes(raw[flags..flags + 4].try_into().unwrap());
    ensure!(
        attributes & !0x240 == 0
            && pointer(&raw, root, width) == 0
            && pointer(&raw, security, width) == 0
            && pointer(&raw, qos, width) == 0,
        "Native section relative/security/attribute semantics unsupported"
    );
    let descriptor = read(
        engine,
        pointer(&raw, name, width),
        if width == 8 { 16 } else { 8 },
    )?;
    let length = u16::from_le_bytes(descriptor[..2].try_into().unwrap()) as usize;
    let maximum = u16::from_le_bytes(descriptor[2..4].try_into().unwrap()) as usize;
    ensure!(
        length > 0 && length <= 8192 && length % 2 == 0 && maximum >= length,
        "Native section counted name invalid or unbounded"
    );
    let bytes = read(
        engine,
        pointer(&descriptor, if width == 8 { 8 } else { 4 }, width),
        length as u64,
    )?;
    let units: Vec<_> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let name = String::from_utf16(&units)?;
    let namespace = engine
        .get_data()
        .machine
        .object_namespace()
        .ok_or_else(|| {
            anyhow::anyhow!("Object-directory inventory is not explicitly configured")
        })?;
    let status = match namespace.section(&name, attributes & 0x40 != 0)? {
        SectionLookup::Failure { status } => status,
        SectionLookup::Present { .. } => {
            bail!("Section exists but owned access/handle lifetime is not modeled")
        }
    };
    // Snapshot status resolution performs no guest writes. Validate the entire
    // final output and typed-memory guards before committing its one effect.
    require(engine, args[0], width as u64, P::WRITE)?;
    super::mdl::require_api_write(engine, args[0], width as u64)?;
    if let Err(error) = crate::cpu::write(engine, args[0], &[0; 8][..width]) {
        engine
            .get_data_mut()
            .apis
            .kernel_sections
            .native_effect_failure = true;
        return Err(error);
    }
    let event = Event {
        instruction_ordinal: engine.get_data().instructions,
        name,
        desired_access: args[1] as u32,
        attributes,
        status,
        output_cleared: true,
    };
    let state = &mut engine.get_data_mut().apis.kernel_sections;
    if state.events.len() < 128 {
        state.events.push(event);
    } else {
        state.omitted = state.omitted.saturating_add(1);
    }
    Ok(status as u64)
}
