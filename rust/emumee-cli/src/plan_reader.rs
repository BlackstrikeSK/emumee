//! Read-only plan inspection. Fixed opaque input slots never become guest paths.
use anyhow::Result;
#[cfg(windows)]
use anyhow::ensure;
use serde_json::Value;
use std::path::Path;

#[cfg(windows)]
pub(crate) fn acquire(
    plan_path: &Path,
    staged_root: &Path,
) -> Result<emumee_core::analysis_plan::PreparedIntake> {
    use anyhow::{Context, ensure};
    use emumee_core::analysis_plan::{
        MAX_INPUTS, MAX_INVENTORY_BYTES, MAX_PLAN_BYTES, PlanSpec, PreparedIntake,
    };
    use emumee_platform::windows::read_regular;
    let raw = read_regular(plan_path, MAX_PLAN_BYTES, None)
        .context("Analysis plan could not be safely read")?;
    let spec = PlanSpec::decode(&raw).context("Analysis plan decode failed")?;
    ensure!(
        !spec.inputs.is_empty() && spec.inputs.len() <= MAX_INPUTS,
        "Analysis input count exceeds compiled bounds"
    );
    let mut total = 0u64;
    for input in &spec.inputs {
        ensure!(
            input.size <= emumee_core::pe::MAX_INPUT as u64,
            "Analysis input exceeds128MiB"
        );
        total = total
            .checked_add(input.size)
            .context("Analysis input reservation overflow")?;
        ensure!(
            total <= MAX_INVENTORY_BYTES,
            "Analysis inventory exceeds256MiB"
        );
    }
    let root = std::path::absolute(staged_root).context("Invalid staged input directory")?;
    let mut buffers = Vec::with_capacity(spec.inputs.len());
    for (index, input) in spec.inputs.iter().enumerate() {
        let slot = root.join("inputs").join(format!("{index:04}.bin"));
        let bytes = read_regular(&slot, usize::try_from(input.size)?, Some(&root))
            .with_context(|| format!("Analysis input slot{index:04} could not be safely read"))?;
        buffers.push(bytes);
    }
    PreparedIntake::prepare(raw, buffers)
        .context("Analysis plan or input bytes failed identity, format or planning validation")
}

#[cfg(windows)]
pub fn inspect(plan_path: &Path, staged_root: &Path) -> Result<Value> {
    let intake = acquire(plan_path, staged_root)?;
    let plan = intake.resolved();
    ensure!(
        !plan.executable(),
        "Read-only inspection cannot authorize execution"
    );
    // The verified inventory proves each declared digest matches these exact
    // safely-read buffers. Preserve their physical opaque slot order for a
    // future parent-side stage; this receipt is never execution authority.
    let verified_slots: Vec<_> = intake
        .slots()
        .enumerate()
        .map(|(index, (input, bytes))| {
            serde_json::json!({
                "slot":format!("inputs/{index:04}.bin"),
                "id":&input.id,
                "size":bytes.len(),
                "sha256":&input.sha256,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "schema":"emumee.analysis_plan_inspection.v1",
        "executable":false,
        "engine_applied":false,
        "plan_sha256":plan.sha256(),
        "request_sha256":plan.request_sha256(),
        "input_slots_verified":intake.slots().len(),
        "input_bytes_verified":intake.slots().map(|(_, bytes)| bytes.len() as u64).sum::<u64>(),
        "verified_slots":verified_slots,
        "plan":plan.value(),
        "scope":"Read-only inspection of exact safely-read buffers and opaque ordered slot identities; no worker, broker, staging writes or guest execution. A later controller must re-read and re-verify bytes before use. Unreferenced files in the selected directory were not read or qualified."
    }))
}

#[cfg(not(windows))]
pub fn inspect(plan_path: &Path, staged_root: &Path) -> Result<Value> {
    let _ = (plan_path, staged_root);
    anyhow::bail!("Verified analysis planning requires the Windows regular-file reader")
}
