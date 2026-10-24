//! Explicit ordinary-engine capture. Guest completion and permissions are immutable.
use super::*;
use anyhow::Context;
use emumee_core::{
    artifact_bridge::{Origin, capture_owned_budgeted},
    artifacts::{ArtifactCatalog, ArtifactKind, CaptureSummary},
    capture_profile::CaptureProfile,
    driver_runtime::{Ledger, Marker, READ_LIMIT, Receipt, SCAN_LIMIT, WORK_LIMIT},
    driver_runtime_fixture::Case,
    report_bundle::digest,
};
use serde_json::json;
use std::collections::BTreeMap;

const POOL_SNAPSHOT_LIMIT: u64 = 16 * 1024 * 1024;
const POOL_SNAPSHOT_COUNT_LIMIT: usize = 256;
const STACK_SNAPSHOT_LIMIT: u64 = 4 * 1024 * 1024;

pub(super) struct Prepared {
    case: Option<Case>,
}
impl Prepared {
    fn owned(case: Case) -> Self {
        Self { case: Some(case) }
    }
    pub(super) fn submitted() -> Self {
        Self { case: None }
    }
}
pub(super) struct State {
    pub receipt: Receipt,
    read_limit: u64,
}
pub(super) fn install(
    engine: &mut NativeEngine,
    prepared: Prepared,
    pe: &PeImage,
    input: &[u8],
    base: u64,
) -> Result<()> {
    configured::require_unpublished(engine.get_data())?;
    ensure!(
        engine.get_data().capture.is_none() && engine.get_data().apis.captures.items.is_empty(),
        "Capture policy already installed"
    );
    ensure!(
        pe.sample.kind == emumee_core::pe::Kind::Driver
            && pe.sample.architecture == Architecture::X64
            && match prepared.case {
                Some(case) => pe.image_size as usize == case.image_bytes(),
                None => pe.image_size as u64 <= SCAN_LIMIT,
            },
        "Runtime capture target exceeds the bounded driver profile"
    );
    let case = prepared.case;
    let read_limit = if case == Some(Case::ReadBudget) {
        1024
    } else {
        READ_LIMIT
    };
    let scan_limit = if case == Some(Case::ScanBudget) {
        pe.image_size as u64 - 1
    } else {
        SCAN_LIMIT
    };
    let work_limit = if case == Some(Case::WorkBudget) {
        0
    } else {
        WORK_LIMIT
    };
    let retention = if case == Some(Case::RetentionBudget) {
        1024
    } else {
        256 * 1024 * 1024
    };
    let mut catalog =
        ArtifactCatalog::with_retention_budget(CaptureProfile::Driver128V1, retention)
            .context("Compiled retention budget")?;
    ensure!(
        catalog.set_carving_limits(scan_limit as usize, work_limit),
        "Compiled carving budget"
    );
    engine.get_data_mut().apis.captures = catalog;
    engine.get_data_mut().capture = Some(State {
        receipt: Receipt {
            version: "emumee.driver-runtime.v1".into(),
            profile: "driver128_v1".into(),
            sources: [
                "guest_files",
                "registry_binary",
                "memory_snapshots",
                "structural_pe",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            input_sha256: digest(input),
            initial_image_sha256: String::new(),
            initial_image_phase: "materialized_relocated_before_imports".into(),
            post_image_sha256: None,
            image_base: base,
            image_bytes: pe.image_size as u64,
            selected_read_complete: false,
            capture_complete: false,
            read_limit,
            scan_limit,
            work_limit,
            retention_limit: retention as u64,
            ledger: Ledger::default(),
            boundary_instructions: 0,
            boundary_pc: 0,
            markers: case
                .map(Case::markers)
                .unwrap_or_default()
                .into_iter()
                .map(|(rva, initial, expected)| Marker {
                    rva,
                    initial,
                    expected,
                    observed: None,
                })
                .collect(),
            omissions: Vec::new(),
            scope: if case.is_none() {
                "Submitted driver: settled guest READ bytes and structural reconstruction; capture completeness is not confirmed unpacking".into()
            } else {
                "Settled guest READ bytes and structural reconstruction only; no confirmed unpacking".into()
            },
        },
        read_limit,
    });
    Ok(())
}
pub(super) fn materialized(engine: &mut Unicorn<Trace>, base: u64, image: &[u8]) {
    if let Some(state) = engine.get_data_mut().capture.as_mut() {
        if state.receipt.image_base == base {
            state.receipt.initial_image_sha256 = digest(image);
            for marker in &mut state.receipt.markers {
                if let Some(initial) = image.get(marker.rva as usize) {
                    marker.initial = *initial;
                }
            }
        }
    }
}
pub(super) fn report(engine: &mut Unicorn<Trace>, catalog: &ArtifactCatalog) -> Option<Receipt> {
    let (scan, work) = catalog.carving_totals();
    let state = engine.get_data_mut().capture.as_mut()?;
    state.receipt.ledger.scan_bytes = scan as u64;
    state.receipt.ledger.carving_work_bytes = work;
    if catalog.summary.omitted_observations > 0 {
        state.receipt.capture_complete = false;
        if state.receipt.omissions.is_empty() {
            state
                .receipt
                .omissions
                .push("selected_capture_sources_omitted".into());
        }
    }
    Some(state.receipt.clone())
}
fn omit(engine: &mut Unicorn<Trace>, bytes: u64, reason: &str) {
    let state = engine.get_data_mut();
    if let Some(capture) = state.capture.as_mut() {
        if capture.receipt.omissions.len() < 32 {
            capture.receipt.omissions.push(reason.to_owned());
        }
    }
    let _ = state.apis.captures.merge_omissions(&CaptureSummary {
        omitted_observations: 1,
        omitted_bytes: bytes,
        reasons: BTreeMap::from([(reason.to_owned(), 1)]),
    });
}
/// Shared capture-only read work, preserving the separate MDL32MiB subcap.
pub(super) fn reserve_read(engine: &mut Unicorn<Trace>, bytes: u64) -> bool {
    let Some(state) = engine.get_data_mut().capture.as_mut() else {
        return true;
    };
    let allowed = state.receipt.ledger.reserve_read(bytes, state.read_limit);
    if !allowed {
        omit(engine, bytes, "capture_read_budget");
    }
    allowed
}
fn read_succeeded(engine: &mut Unicorn<Trace>, bytes: u64) {
    if let Some(state) = engine.get_data_mut().capture.as_mut() {
        state.receipt.ledger.read_bytes += bytes;
        debug_assert!(state.receipt.ledger.read_bytes <= state.receipt.ledger.read_reserved_bytes);
    }
}
pub(super) fn aux_skipped(engine: &mut Unicorn<Trace>, bytes: u64) {
    if engine.get_data().capture.is_some() {
        omit(engine, bytes, "capture_aux_not_readable_or_subcap");
    }
}
pub(super) fn memory_record(engine: &mut Unicorn<Trace>, bytes: Vec<u8>, source: &str, path: &str) {
    if engine.get_data().capture.is_none() {
        engine
            .get_data_mut()
            .apis
            .captures
            .add(bytes, ArtifactKind::MemorySnapshot, source, path);
        return;
    }
    let size = bytes.len();
    read_succeeded(engine, size as u64);
    let context = json!({"guest_memory_path":path,"capture_boundary":"settled"})
        .as_object()
        .unwrap()
        .clone();
    let result = capture_owned_budgeted(
        &mut engine.get_data_mut().apis.captures,
        bytes,
        source,
        Some(&context),
        Origin::Memory,
        true,
    );
    if result.is_err() {
        omit(engine, size as u64, "capture_bridge_failure");
    }
}

/// Copy live pool mappings at the settled boundary, including mapped page slack.
/// Allocation metadata remains provenance, never evidence of code execution.
pub(super) fn live_pool(engine: &mut Unicorn<Trace>) {
    if engine.get_data().capture.is_none() {
        return;
    }
    let allocations = engine
        .get_data()
        .apis
        .pool
        .allocations
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut selected_bytes = 0u64;
    for (index, allocation) in allocations.into_iter().enumerate() {
        let size = allocation.mapped;
        if index >= POOL_SNAPSHOT_COUNT_LIMIT
            || selected_bytes
                .checked_add(size)
                .is_none_or(|total| total > POOL_SNAPSHOT_LIMIT)
        {
            omit(engine, size, "capture_live_pool_subcap");
            continue;
        }
        selected_bytes += size;
        if !engine
            .get_data()
            .apis
            .memory
            .allows(allocation.base, size, Permissions::READ)
        {
            omit(engine, size, "capture_live_pool_not_readable");
            continue;
        }
        if !reserve_read(engine, size) {
            continue;
        }
        let Ok(bytes) = engine.mem_read_as_vec(allocation.base, size as usize) else {
            omit(engine, size, "capture_live_pool_read_failed");
            continue;
        };
        read_succeeded(engine, size);
        let path = format!("memory:kernel_pool:0x{:x}", allocation.base);
        let context = json!({
            "guest_memory_path": path,
            "capture_boundary": "settled",
            "guest_base": allocation.base,
            "mapped_bytes": allocation.mapped,
            "requested_bytes": allocation.requested,
            "pool_tag": allocation.tag,
            "executable": allocation.executable,
            "paged": allocation.paged,
            "no_fixups": true,
        })
        .as_object()
        .unwrap()
        .clone();
        if capture_owned_budgeted(
            &mut engine.get_data_mut().apis.captures,
            bytes,
            "kernel_pool_allocation",
            Some(&context),
            Origin::Memory,
            true,
        )
        .is_err()
        {
            omit(engine, size, "capture_live_pool_bridge_failure");
        }
    }
}

/// Retain modeled kernel stacks at the settled boundary. These are diagnostic
/// snapshots of stack state, not reconstructed executable images.
pub(super) fn live_stacks(engine: &mut Unicorn<Trace>) {
    if engine.get_data().capture.is_none() {
        return;
    }
    let stacks = engine
        .get_data()
        .apis
        .memory
        .regions()
        .filter(|region| {
            matches!(
                region.tag.as_str(),
                "kernel fixture stack" | "system thread stack" | "IPI processor callback stack"
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut selected_bytes = 0u64;
    for region in stacks {
        if selected_bytes
            .checked_add(region.size)
            .is_none_or(|total| total > STACK_SNAPSHOT_LIMIT)
        {
            omit(engine, region.size, "capture_live_stack_subcap");
            continue;
        }
        selected_bytes += region.size;
        if !region.permissions.contains(Permissions::READ) {
            omit(engine, region.size, "capture_live_stack_not_readable");
            continue;
        }
        if !reserve_read(engine, region.size) {
            continue;
        }
        let Ok(bytes) = engine.mem_read_as_vec(region.base, region.size as usize) else {
            omit(engine, region.size, "capture_live_stack_read_failed");
            continue;
        };
        read_succeeded(engine, region.size);
        let path = format!("memory:kernel_stack:0x{:x}", region.base);
        let context = json!({
            "guest_memory_path": path,
            "capture_boundary": "settled",
            "guest_base": region.base,
            "mapped_bytes": region.size,
            "modeled_region_tag": region.tag,
            "no_fixups": true,
        })
        .as_object()
        .unwrap()
        .clone();
        if capture_owned_budgeted(
            &mut engine.get_data_mut().apis.captures,
            bytes,
            "kernel_stack_mapping",
            Some(&context),
            Origin::Memory,
            true,
        )
        .is_err()
        {
            omit(engine, region.size, "capture_live_stack_bridge_failure");
        }
    }
}
/// Returns false for an old role, allowing its exact legacy bridge to proceed.
pub(super) fn registry_binary(
    engine: &mut Unicorn<Trace>,
    key: &str,
    name: &str,
    bytes: &[u8],
) -> bool {
    if engine.get_data().capture.is_none() {
        return false;
    }
    let context = json!({"registry_key":key,"registry_value":name,"registry_type":3})
        .as_object()
        .unwrap()
        .clone();
    let captures = &mut engine.get_data_mut().apis.captures;
    captures.add_with_context(
        bytes.to_vec(),
        ArtifactKind::RegistryValue,
        "registry_value",
        &format!("{key}\\{name}"),
        Some(context.clone()),
    );
    if capture_owned_budgeted(
        captures,
        bytes.to_vec(),
        "registry_value",
        Some(&context),
        Origin::RegistryValue,
        false,
    )
    .is_err()
    {
        omit(engine, bytes.len() as u64, "registry_capture_failed");
    }
    true
}
pub(super) fn settled(engine: &mut Unicorn<Trace>, pc: u64) -> Result<()> {
    let Some(state) = engine.get_data().capture.as_ref() else {
        return Ok(());
    };
    let base = state.receipt.image_base;
    let length = state.receipt.image_bytes;
    {
        let count = engine.get_data().instructions;
        let state = engine.get_data_mut().capture.as_mut().unwrap();
        state.receipt.boundary_instructions = count;
        state.receipt.boundary_pc = pc;
    }
    if !engine
        .get_data()
        .apis
        .memory
        .allows(base, length, Permissions::READ)
    {
        omit(engine, length, "capture_root_not_readable");
        return Ok(());
    }
    if !reserve_read(engine, length) {
        return Ok(());
    }
    let mut bytes = vec![0u8; length as usize];
    for (offset, chunk) in bytes.chunks_mut(8 * 1024 * 1024).enumerate() {
        let address = base
            .checked_add((offset * 8 * 1024 * 1024) as u64)
            .context("Capture address overflow")?;
        if !engine
            .get_data()
            .apis
            .memory
            .allows(address, chunk.len() as u64, Permissions::READ)
            || engine.mem_read(address, chunk).is_err()
        {
            omit(engine, length, "capture_root_read_failed");
            return Ok(());
        }
        read_succeeded(engine, chunk.len() as u64);
    }
    {
        let state = engine.get_data_mut().capture.as_mut().unwrap();
        state.receipt.post_image_sha256 = Some(digest(&bytes));
        state.receipt.selected_read_complete = true;
        for marker in &mut state.receipt.markers {
            marker.observed = bytes.get(marker.rva as usize).copied();
        }
    }
    let before = engine.get_data().apis.captures.summary.omitted_observations;
    let context=json!({"guest_base":base,"capture_boundary":"settled","runtime_marker_rvas":engine.get_data().capture.as_ref().unwrap().receipt.markers.iter().map(|m|m.rva).collect::<Vec<_>>()}).as_object().unwrap().clone();
    let result = emumee_core::artifact_bridge::capture_owned_mapped_root(
        &mut engine.get_data_mut().apis.captures,
        bytes,
        "settled_root_image",
        Some(&context),
    );
    if result.is_err() {
        omit(engine, length, "capture_bridge_failure");
    }
    let captures = &engine.get_data().apis.captures;
    let (scan, work) = captures.carving_totals();
    let omitted = captures.summary.omitted_observations != before;
    let retained_snapshot = captures.items.iter().any(|item| {
        Some(item.sha256.as_str())
            == engine
                .get_data()
                .capture
                .as_ref()
                .unwrap()
                .receipt
                .post_image_sha256
                .as_deref()
            && item
                .observations
                .iter()
                .any(|o| o.kind == ArtifactKind::MemorySnapshot)
    });
    let state = engine.get_data_mut().capture.as_mut().unwrap();
    state.receipt.ledger.scan_bytes = scan as u64;
    state.receipt.ledger.carving_work_bytes = work;
    if omitted && state.receipt.omissions.len() < 32 {
        state
            .receipt
            .omissions
            .push("capture_scan_or_retention_omitted".into());
    }
    state.receipt.capture_complete = retained_snapshot
        && !omitted
        && result.is_ok_and(|s| s.scan_complete)
        && state
            .receipt
            .markers
            .iter()
            .all(|m| m.observed == Some(m.expected));
    Ok(())
}
pub fn run_owned(case: Case) -> Result<Execution> {
    let bytes = case.bytes();
    run_generated_with_fixture_configuration(
        &bytes,
        &[],
        1000,
        120_000_000,
        GeneratedConfiguration {
            capture: Some(Prepared::owned(case)),
            ..Default::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn live_stack_snapshot_preserves_generated_guest_memory_and_registers() {
        let mut engine = new_engine(Architecture::X64).unwrap();
        let input = Case::Tiny.bytes();
        let pe = PeImage::parse(&input, "owned.sys").unwrap();
        install(
            &mut engine,
            Prepared::owned(Case::Tiny),
            &pe,
            &input,
            pe.image_base,
        )
        .unwrap();
        let base = 0xffff_a000_1000_0000;
        let original = vec![0xa5; 8192];
        engine.mem_map(base, 8192, Prot::READ | Prot::WRITE).unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(base, 8192, Permissions::RW, None, "kernel fixture stack")
            .unwrap();
        engine.mem_write(base, &original).unwrap();
        engine.reg_write(RegisterX86::RAX, 0x1234).unwrap();

        live_stacks(&mut engine);

        assert_eq!(engine.mem_read_as_vec(base, 8192).unwrap(), original);
        assert_eq!(engine.reg_read(RegisterX86::RAX).unwrap(), 0x1234);
        let item = engine
            .get_data()
            .apis
            .captures
            .items
            .iter()
            .find(|item| {
                item.observations
                    .iter()
                    .any(|row| row.source.starts_with("kernel_stack_mapping"))
            })
            .unwrap();
        assert_eq!(item.data, original);
        let context = item.observations[0].context.as_ref().unwrap();
        assert_eq!(context["guest_base"], base);
        assert_eq!(context["mapped_bytes"], 8192);
        assert_eq!(context["modeled_region_tag"], "kernel fixture stack");
    }

    #[test]
    fn live_pool_snapshot_includes_executable_mapping_and_page_slack_without_guest_mutation() {
        let mut engine = new_engine(Architecture::X64).unwrap();
        let input = Case::Tiny.bytes();
        let pe = PeImage::parse(&input, "owned.sys").unwrap();
        install(
            &mut engine,
            Prepared::owned(Case::Tiny),
            &pe,
            &input,
            pe.image_base,
        )
        .unwrap();
        let allocation = engine
            .get_data()
            .apis
            .pool
            .prepare(
                &engine.get_data().apis.memory,
                Architecture::X64,
                0x80,
                124,
                0x54534554,
                0,
            )
            .unwrap()
            .unwrap();
        engine
            .mem_map(allocation.base, allocation.mapped, Prot::ALL)
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(
                allocation.base,
                allocation.mapped,
                allocation.permissions(),
                None,
                "generated executable pool",
            )
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .pool
            .commit_allocation(allocation.clone());
        let mut original = vec![0xcd; allocation.mapped as usize];
        original[..4].copy_from_slice(&[0x90, 0x90, 0xc3, 0x00]);
        original[allocation.mapped as usize - 1] = 0xa5;
        engine.mem_write(allocation.base, &original).unwrap();
        engine.reg_write(RegisterX86::RAX, 0x1234).unwrap();

        live_pool(&mut engine);

        assert_eq!(
            engine
                .mem_read_as_vec(allocation.base, allocation.mapped as usize)
                .unwrap(),
            original
        );
        assert_eq!(engine.reg_read(RegisterX86::RAX).unwrap(), 0x1234);
        let item = engine
            .get_data()
            .apis
            .captures
            .items
            .iter()
            .find(|item| {
                item.observations
                    .iter()
                    .any(|row| row.source.starts_with("kernel_pool_allocation"))
            })
            .unwrap();
        assert_eq!(item.data, original);
        let context = item.observations[0].context.as_ref().unwrap();
        assert_eq!(context["guest_base"], allocation.base);
        assert_eq!(context["requested_bytes"], 124);
        assert_eq!(context["mapped_bytes"], allocation.mapped);
        assert_eq!(context["executable"], true);
        assert_eq!(
            engine
                .get_data()
                .capture
                .as_ref()
                .unwrap()
                .receipt
                .ledger
                .read_bytes,
            allocation.mapped
        );
    }
    #[test]
    fn tiny_real_execution_mutates_both_snapshot_and_reconstructed_bytes() {
        let value = run_owned(Case::Tiny).unwrap();
        assert_eq!(value.guest_entry_return, Some(17));
        let report = value.capture_runtime.as_ref().unwrap();
        assert!(report.capture_complete && report.selected_read_complete);
        assert_ne!(
            report.initial_image_sha256,
            report.post_image_sha256.as_deref().unwrap()
        );
        assert!(
            report
                .markers
                .iter()
                .all(|m| m.observed == Some(m.expected) && m.initial != m.expected)
        );
        let snapshot = value.artifacts.iter().find(|a| a.size == 16384).unwrap();
        assert_eq!(snapshot.data[0x2010], 0xa7);
        assert_eq!(snapshot.data[16384 - 16], 0xb3);
        let raw = value.artifacts.iter().find(|a| a.size == 1536).unwrap();
        assert_eq!(raw.data[1040], 0xa7);
        assert_ne!(raw.sha256, report.input_sha256);
    }
    #[test]
    fn gaps_and_all_capture_budgets_leave_real_guest_completion_untouched() {
        for case in [
            Case::Gap,
            Case::ReadBudget,
            Case::ScanBudget,
            Case::WorkBudget,
            Case::RetentionBudget,
        ] {
            let value = run_owned(case).unwrap();
            assert_eq!(value.guest_entry_return, Some(17));
            assert_eq!(value.completion_reason, "entry_return");
            let r = value.capture_runtime.unwrap();
            assert!(!r.capture_complete);
            assert!(!r.omissions.is_empty());
            assert!(value.capture_summary.omitted_observations > 0);
        }
    }
    #[test]
    fn installed_capture_policy_cannot_be_replaced_after_publication() {
        let mut engine = new_engine(Architecture::X64).unwrap();
        let bytes = Case::Tiny.bytes();
        let pe = PeImage::parse(&bytes, "owned.sys").unwrap();
        install(
            &mut engine,
            Prepared::owned(Case::Tiny),
            &pe,
            &bytes,
            pe.image_base,
        )
        .unwrap();
        engine.get_data_mut().instructions = 1;
        assert!(
            install(
                &mut engine,
                Prepared::owned(Case::Tiny),
                &pe,
                &bytes,
                pe.image_base
            )
            .is_err()
        );
    }
    #[test]
    fn ordinary_execution_catalog_and_marker_ranges_bind_the_driver_report() {
        use emumee_core::driver_capture_reports::{
            self as reports, Binding, Mode, Stop, VerifiedProjection,
        };
        let mut run = run_owned(Case::Tiny).unwrap();
        let public = serde_json::to_value(&run).unwrap();
        let reference: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../emumee-core/tests/data/driver_runtime_reference.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let expected = &reference["cases"][0];
        assert_eq!(
            run.capture_runtime.as_ref().unwrap().initial_image_sha256,
            expected["initial_image_sha256"].as_str().unwrap()
        );
        assert_eq!(
            run.capture_runtime
                .as_ref()
                .unwrap()
                .post_image_sha256
                .as_deref(),
            expected["post_image_sha256"].as_str()
        );
        let binding = Binding {
            request_sha256: "1".repeat(64),
            input_sha256: run.capture_runtime.as_ref().unwrap().input_sha256.clone(),
            input_bytes: 1536,
            recipe: "runtime-tiny".into(),
            source_tree_sha256: "2".repeat(64),
            containment_sha256: "3".repeat(64),
        };
        let catalog = ArtifactCatalog::from_owned_parts(
            CaptureProfile::Driver128V1,
            std::mem::take(&mut run.artifacts),
            std::mem::take(&mut run.capture_summary),
            256 * 1024 * 1024,
        )
        .unwrap();
        let bundle = reports::build(
            "20261018T120000Z-12345678",
            &binding,
            Mode::GeneratedDriverCapture,
            &public,
            Stop::Normal,
            false,
            &catalog,
        )
        .unwrap();
        let checked = reports::verify(
            &bundle.summary,
            &bundle.engine,
            &bundle.network,
            &bundle.manifest,
            &bundle.checkpoint,
            &binding,
            |record| {
                let payload = catalog
                    .items
                    .iter()
                    .find(|a| a.sha256 == record.sha256)
                    .unwrap();
                VerifiedProjection::for_record(record, |offset, count| {
                    Some(payload.data[offset as usize..offset as usize + count].to_vec())
                })
            },
        )
        .unwrap();
        assert_eq!(checked.summary.status, "completed");
        for field in ["artifacts", "capture_summary"] {
            let mut changed = public.clone();
            changed[field] = serde_json::Value::Null;
            assert!(
                reports::build(
                    "20261018T120000Z-12345678",
                    &binding,
                    Mode::GeneratedDriverCapture,
                    &changed,
                    Stop::Normal,
                    false,
                    &catalog
                )
                .is_err()
            );
        }
        let mut changed = public;
        changed["capture_runtime"]["markers"][0]["expected"] = json!(0x11);
        changed["capture_runtime"]["markers"][0]["observed"] = json!(0x11);
        assert!(
            reports::build(
                "20261018T120000Z-12345678",
                &binding,
                Mode::GeneratedDriverCapture,
                &changed,
                Stop::Normal,
                false,
                &catalog
            )
            .is_err()
        );
    }
}
