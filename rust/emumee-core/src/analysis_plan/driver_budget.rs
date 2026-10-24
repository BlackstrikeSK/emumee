//! Pure resource projection only; it does not resolve/enable a general run.
use super::{inventory::Inspection, *};
use serde_json::{Value, json};
use std::collections::BTreeSet;
const M: u64 = 1024 * 1024;
fn add(values: impl IntoIterator<Item = u64>) -> Result<u64> {
    values.into_iter().try_fold(0u64, |a, b| {
        a.checked_add(b).ok_or_else(|| {
            problem(
                "budget_overflow",
                "limits",
                "Driver peak/physical sum overflow",
            )
        })
    })
}
pub fn project_driver_resources(spec: &PlanSpec, inventory: &VerifiedInventory) -> Result<Value> {
    demand(
        identity(
            b"emumee.analysis.inventory.intent.v1\0",
            &canonical(&spec.inputs)?,
        ) == inventory.intent_digest,
        "inventory_intent",
        "inputs",
        "Verified input intent changed",
    )?;
    demand(
        spec.capture.profile == CaptureProfile::LargeDriver128V1
            && spec.reports.profile == ReportProfile::LargeDriverV1,
        "unsupported_profile",
        "capture.profile",
        "Explicit matching large capture/report profile required",
    )?;
    let Target::KernelDriver {
        input,
        architecture: Arch::X64,
        unload: false,
        code_reference: Reference::None,
        ..
    } = &spec.target
    else {
        return Err(problem(
            "unsupported_driver_projection",
            "target",
            "Initial resource projection is x64 DriverEntry without unload/code reference",
        ));
    };
    demand(
        spec.companions.is_empty(),
        "unsupported_driver_projection",
        "companions",
        "Companion graph runtime/resource qualification remains pending",
    )?;
    let root = inventory.entries.get(input).ok_or_else(|| {
        problem(
            "missing_input",
            "target.input",
            "Actual verified root bytes absent",
        )
    })?;
    let image = match root.inspection {
        Inspection::Pe {
            architecture: Arch::X64,
            ref kind,
            managed: false,
            image_size,
            ..
        } if kind == "driver" => image_size as u64,
        _ => {
            return Err(problem(
                "target_mismatch",
                "target.input",
                "Actual x64 unmanaged driver required",
            ));
        }
    };
    demand(
        root.spec.size <= 128 * M && image <= 128 * M && image > 0,
        "driver_size",
        "target.input",
        "Root file/image exceed128MiB profile",
    )?;
    let sources: BTreeSet<_> = spec.capture.sources.iter().copied().collect();
    demand(
        sources.len() == spec.capture.sources.len()
            && sources.contains(&CaptureSource::MemorySnapshots)
            && sources.contains(&CaptureSource::StructuralPe)
            && !sources.contains(&CaptureSource::ContainerStreams),
        "unsupported_capture_sources",
        "capture.sources",
        "Root memory+PE required; runtime container source remains pending",
    )?;
    demand(
        matches!(spec.capture.checkpoint, Checkpoint::FinalBoundary)
            && matches!(spec.capture.memory_strings, MemoryStrings::Disabled),
        "unsupported_option",
        "capture",
        "Only final-boundary byte capture is qualified by this resource model",
    )?;
    demand(
        spec.capture.retained_bytes > 0
            && spec.capture.retained_bytes <= 256 * M
            && spec.capture.memory_scan_bytes >= image
            && spec.capture.memory_scan_bytes <= 128 * M,
        "capture_limit",
        "capture",
        "Driver retention/whole-root scan reservation outside profile",
    )?;
    let l = &spec.limits;
    let r = &spec.reports;
    demand(
        l.max_instructions > 0
            && l.max_instructions <= crate::driver_input::MAX_INSTRUCTIONS
            && l.guest_timeout_ms > 0
            && l.guest_timeout_ms <= 3_600_000
            && l.max_native_api_calls > 0
            && l.max_native_api_calls <= 100000,
        "execution_limit",
        "limits",
        "Native budget/API/timeout must be representable, never clamped",
    )?;
    demand(
        l.worker_memory_mb == 2048 && l.broker_memory_mb == 256,
        "job_limit",
        "limits.worker_memory_mb",
        "Separate explicit2048MiB worker/256MiB broker required",
    )?;
    demand(
        l.guest_mapped_bytes >= image
            && l.guest_mapped_bytes <= 512 * M
            && l.guest_heap_bytes <= 256 * M
            && l.guest_pool_bytes <= 256 * M
            && (1..=128).contains(&l.guest_threads),
        "guest_memory_limit",
        "limits",
        "Insufficient/excessive guest resource reservation",
    )?;
    demand(
        l.broker_stream_bytes > 0
            && l.broker_stream_bytes <= 128 * M
            && l.broker_journal_bytes > 0
            && l.broker_journal_bytes <= 64 * M,
        "broker_limit",
        "limits",
        "Both streams and journal require explicit bounded physical copies",
    )?;
    demand(
        r.summary_bytes > 0
            && r.summary_bytes <= 5 * M
            && r.engine_bytes > 0
            && r.engine_bytes <= 50 * M
            && r.network_bytes > 0
            && r.network_bytes <= 64 * M
            && r.manifest_bytes > 0
            && r.manifest_bytes <= M,
        "report_limit",
        "reports",
        "Separate Driver envelope retains bounded document caps",
    )?;
    let fixture_copy = inventory
        .entries
        .values()
        .filter_map(|input| {
            if let Inspection::Fixtures {
                canonical_bytes, ..
            } = input.inspection
            {
                Some(canonical_bytes)
            } else {
                None
            }
        })
        .try_fold(0u64, |a, b| a.checked_add(b))
        .ok_or_else(|| {
            problem(
                "budget_overflow",
                "network",
                "Canonical fixture copy overflow",
            )
        })?;
    let reports = add([
        r.summary_bytes,
        r.summary_bytes,
        r.engine_bytes,
        r.network_bytes,
        r.manifest_bytes,
        r.manifest_bytes,
    ])?;
    let output = add([
        inventory.bytes,
        fixture_copy,
        MAX_PLAN_BYTES as u64,
        reports,
        spec.capture.retained_bytes,
        l.broker_journal_bytes,
        l.broker_stream_bytes,
        l.broker_stream_bytes,
        8 * M,
    ])?;
    demand(
        l.max_output_bytes >= output && l.max_output_bytes <= 1536 * M,
        "output_budget",
        "limits.max_output_bytes",
        "All staged/report/payload/checkpoint/IPC/journal copies must fit",
    )?;
    let entries = add([inventory.entries.len() as u64, 10000, 8, 64])?;
    demand(
        l.max_output_entries as u64 >= entries
            && l.max_output_entries <= 100000
            && (8..=1024).contains(&l.max_output_directories)
            && (4..=40).contains(&l.max_output_depth),
        "output_shape",
        "limits",
        "Flat staging/report/control shape exceeds watchdog reservation",
    )?;
    // Conservative: existing payloads may already fill the catalog when a new scan
    // allocates input/snapshot/reconstruction. No overlap discount is assumed.
    let peak = add([
        l.guest_mapped_bytes,
        l.guest_heap_bytes,
        l.guest_pool_bytes,
        l.guest_threads as u64 * M,
        128 * M,
        inventory.bytes,
        spec.capture.retained_bytes,
        384 * M,
        256 * M,
    ])?;
    demand(
        peak <= 2048 * M,
        "job_budget",
        "limits.worker_memory_mb",
        "Peak omits/fails maps, heaps, pool, stacks, MDL backing, input, catalog, capture transient or runtime headroom",
    )?;
    // Loader materialization<=128MiB is covered by the larger384MiB capture
    // transient phase only while initialization and settled capture cannot overlap.
    let deadline = add([
        l.guest_timeout_ms,
        l.worker_startup_ms,
        l.reporting_grace_ms,
    ])?;
    demand(
        (1..=120000).contains(&l.worker_startup_ms)
            && (1..=120000).contains(&l.reporting_grace_ms)
            && (1..=120000).contains(&l.broker_startup_ms)
            && (1..=120000).contains(&l.broker_grace_ms),
        "deadline_limit",
        "limits",
        "Explicit bounded phase grace required",
    )?;
    Ok(
        json!({"schema":"emumee.driver-resource-projection.v1","executable":false,"graph_resolved":false,"engine_applied":false,"general_worker_admitted":false,"root_image_bytes":image,"single_artifact_bytes":128*M,"retained_bytes":spec.capture.retained_bytes,"aggregate_scan_bytes":spec.capture.memory_scan_bytes,"aggregate_carving_work_bytes":1024*M,"capture_read_work_bytes":192*M,"minimum_output_bytes":output,"minimum_output_entries":entries,"minimum_worker_bytes":peak,"mdl_backing_reservation_bytes":128*M,"capture_transient_bytes":384*M,"loader_transient_bytes":128*M,"transient_phase_maximum_bytes":384*M,"phase_overlap":"loader dropped before guest execution; capture after stop","worker_deadline_ms":deadline,"broker_deadline_ms":add([deadline,l.broker_startup_ms,l.broker_grace_ms])?,"copies":{"input":inventory.bytes,"canonical_fixture":fixture_copy,"request":MAX_PLAN_BYTES,"reports_and_checkpoint":reports,"payloads":spec.capture.retained_bytes,"journal":l.broker_journal_bytes,"request_stream":l.broker_stream_bytes,"response_stream":l.broker_stream_bytes,"receipts":8*M},"scope":"Resource consistency only; original resolve still rejects LargeDriver until all general adapters qualify"}),
    )
}
