//! Narrow privileged mirrors derived exclusively from owned scheduler state.
use super::*;
use emumee_core::kernel_thread_objects::{Ownership, ThreadFields, kernel_apc_disable_word};

#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct CriticalMirror {
    critical_depth: u16,
    raw_kernel_apc_disable: u16,
}
#[derive(Clone, Debug, Serialize)]
pub struct FieldEvidence {
    pub fields: ThreadFields,
    pub critical_depth: u16,
    pub raw_kernel_apc_disable: u16,
    pub scope: &'static str,
}
pub(super) fn report(engine: &Unicorn<Trace>) -> Vec<FieldEvidence> {
    let state = &engine.get_data().apis.thread_objects;
    let model = state.model.borrow();
    let Some(model) = model.as_ref() else {
        return Vec::new();
    };
    let Some(objects) = engine.get_data().apis.objects.model.as_ref() else {
        return Vec::new();
    };
    model.entries.keys().filter_map(|address| {
        let fields = model.thread_fields(objects,*address).ok().flatten()?;
        let mirror = state.critical_mirrors.get(address)?;
        Some(FieldEvidence {
            fields, critical_depth:mirror.critical_depth,
            raw_kernel_apc_disable:mirror.raw_kernel_apc_disable,
            scope:"Pinned x64 build26200 read-only KernelMode, CLIENT_ID and KernelApcDisable mirrors. Last successful mirror is evidence, not a second scheduler state. No SpecialApcDisable, native inline updates, APC delivery or full ETHREAD snapshot.",
        })
    }).collect()
}
pub(super) fn parked_report(
    engine: &Unicorn<Trace>,
) -> Vec<emumee_core::kernel_thread_objects::ParkedPairFields> {
    let model = engine.get_data().apis.thread_objects.model.borrow();
    let Some(model) = model.as_ref() else {
        return Vec::new();
    };
    let Some(objects) = engine.get_data().apis.objects.model.as_ref() else {
        return Vec::new();
    };
    model
        .entries
        .keys()
        .filter_map(|address| model.parked_pair_fields(objects, *address).ok().flatten())
        .collect()
}
fn write(engine: &mut Unicorn<Trace>, address: u64, bytes: &[u8]) -> Result<()> {
    super::super::reference_mapping::require_api_access(
        engine,
        address,
        bytes.len() as u64,
        P::WRITE,
    )?;
    let result = uc(engine.mem_write(address, bytes));
    crate::instruction_window::model_write(engine, address, bytes, result.is_ok());
    result?;
    ensure!(
        uc(engine.mem_read_as_vec(address, bytes.len()))? == bytes,
        "Thread field native mirror readback failed"
    );
    Ok(())
}
pub(super) fn initialize(engine: &mut Unicorn<Trace>, plan: &Plan, address: u64) -> Result<()> {
    let Some(field) = plan.lifetimes.thread_fields(&plan.objects, address)? else {
        return Ok(());
    };
    let life = &plan.lifetimes.entries[&address];
    let depth = match life.role {
        Ownership::InitialCaller => engine.get_data().apis.kernel.save().1,
        Ownership::CreatedSystemThread => crate::threads::saved_critical_depth(engine, life.slot)?,
        Ownership::ParkedProcessor { .. } => crate::ipi::PARKED_CRITICAL_DEPTH,
    };
    write(
        engine,
        address + u64::from(field.previous_mode_offset),
        &[field.previous_mode],
    )?;
    let mut cid = [0; 16];
    cid[..8].copy_from_slice(&field.process_id.to_le_bytes());
    cid[8..].copy_from_slice(&field.thread_id.to_le_bytes());
    write(engine, address + u64::from(field.cid_offset), &cid)?;
    let word = kernel_apc_disable_word(depth);
    write(
        engine,
        address + u64::from(field.kernel_apc_disable_offset),
        &word.to_le_bytes(),
    )?;
    ensure!(
        engine
            .get_data_mut()
            .apis
            .thread_objects
            .critical_mirrors
            .insert(
                address,
                CriticalMirror {
                    critical_depth: depth,
                    raw_kernel_apc_disable: word,
                }
            )
            .is_none(),
        "Thread field mirror already initialized"
    );
    if let Some(pair) = plan.lifetimes.parked_pair_fields(&plan.objects, address)? {
        write(engine, address + u64::from(pair.offset), &pair.bytes())?;
    }
    Ok(())
}
pub(crate) fn sync_critical(engine: &mut Unicorn<Trace>, address: u64) -> Result<()> {
    let field = {
        let model = engine.get_data().apis.thread_objects.model.borrow();
        let Some(model) = model.as_ref() else {
            return Ok(());
        };
        model.thread_fields(objects(engine)?, address)?
    };
    let Some(field) = field else { return Ok(()) };
    // The explicit current identity is supplied by CPU context switching, which
    // temporarily takes the scheduler out of Trace. Do not infer a root fallback.
    let depth = engine.get_data().apis.kernel.save().1;
    let prior = engine
        .get_data()
        .apis
        .thread_objects
        .critical_mirrors
        .get(&address)
        .copied();
    engine.get_data_mut().apis.thread_objects.native_failure = true;
    engine.get_data_mut().apis.thread_objects.last_effect = Some(NativeEffect {
        object: address,
        operation: "mirror_kernel_apc_disable",
    });
    let prior = prior.ok_or_else(|| anyhow::anyhow!("Thread critical counter mirror missing"))?;
    let at = address + u64::from(field.kernel_apc_disable_offset);
    ensure!(
        uc(engine.mem_read_as_vec(at, 2))? == prior.raw_kernel_apc_disable.to_le_bytes(),
        "Thread critical counter diverged from last owned mirror; refusing repair"
    );
    if depth != prior.critical_depth {
        let word = kernel_apc_disable_word(depth);
        write(engine, at, &word.to_le_bytes())?;
        engine
            .get_data_mut()
            .apis
            .thread_objects
            .critical_mirrors
            .insert(
                address,
                CriticalMirror {
                    critical_depth: depth,
                    raw_kernel_apc_disable: word,
                },
            );
    }
    engine.get_data_mut().apis.thread_objects.native_failure = false;
    Ok(())
}
