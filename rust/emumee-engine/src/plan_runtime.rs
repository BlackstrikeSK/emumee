//! Sealed closed-role adapter. No bytes are regenerated after validation.
use super::*;
use emumee_core::{
    artifacts::ArtifactCatalog, capture_profile::CaptureProfile, plan_runtime::PreparedAnalysis,
};
pub fn execute(
    prepared: &PreparedAnalysis,
    broker: Box<dyn emumee_core::broker::Client>,
) -> Result<Execution> {
    ensure!(
        !prepared.request().case.static_only(),
        "Static analysis has no native entry"
    );
    let configured = configured::Prepared::closed_plan(prepared)?;
    let catalog = ArtifactCatalog::with_retention_budget(
        CaptureProfile::Legacy32V1,
        prepared.spec().capture.retained_bytes as usize,
    )
    .ok_or_else(|| anyhow!("Closed legacy capture budget"))?;
    run_generated_with_fixture_configuration(
        prepared.input(),
        &[],
        prepared.spec().limits.max_instructions,
        prepared.spec().limits.guest_timeout_ms * 1000,
        GeneratedConfiguration {
            configured: Some(configured),
            plan_catalog: Some(catalog),
            plan_limits: Some(prepared.spec().limits.clone()),
            plan_fault: prepared.request().fault,
            ..Default::default()
        }
        .with_plan_broker(broker),
    )
}
pub(super) fn check_limits(engine: &mut Unicorn<Trace>) -> Result<()> {
    if engine.get_data().plan_fault == emumee_core::plan_runtime::Fault::Reconfigure
        && engine.get_data().instructions > 0
    {
        let before = serde_json::to_value(engine.get_data().machine.receipt())?;
        // Use the same real publication guard as prepublication installation.
        // The guard rejects before any model replacement is attempted.
        let error = configured::require_unpublished(engine.get_data())
            .err()
            .ok_or_else(|| anyhow!("Published configuration unexpectedly mutable"))?;
        let after = serde_json::to_value(engine.get_data().machine.receipt())?;
        ensure!(
            before == after,
            "Refused reconfiguration changed installed receipt"
        );
        let instructions = engine.get_data().instructions;
        engine.get_data_mut().plan_fault_evidence = Some(
            serde_json::json!({"scenario":"reconfigure","attempted_after_instructions":instructions,"refused":true,"configuration_unchanged":before == after,"before":before,"after":after,"reason":error.to_string()}),
        );
        return Err(error.context("Closed postpublication reconfiguration refused"));
    }
    let trace = engine.get_data();
    let Some(limits) = &trace.plan_limits else {
        return Ok(());
    };
    let mapped = trace
        .apis
        .memory
        .regions()
        .try_fold(0u64, |total, r| total.checked_add(r.size))
        .ok_or_else(|| anyhow!("Closed plan mapping accounting overflow"))?;
    // This sealed profile sets all three selected byte caps to128MiB. Aggregate
    // mapped backing is the stronger bound, including all heap and pool pages.
    ensure!(
        mapped <= limits.guest_mapped_bytes
            && mapped <= limits.guest_heap_bytes
            && mapped <= limits.guest_pool_bytes,
        "Closed plan guest backing quota exceeded"
    );
    ensure!(
        trace.apis.calls <= limits.max_native_api_calls as u64,
        "Closed plan API quota exceeded"
    );
    Ok(())
}
pub(super) fn before_api(engine: &Unicorn<Trace>) -> Result<()> {
    if let Some(limits) = &engine.get_data().plan_limits {
        ensure!(
            engine.get_data().apis.calls < limits.max_native_api_calls as u64,
            "Closed plan API quota reached before dispatch"
        );
    }
    Ok(())
}
impl GeneratedConfiguration {
    fn with_plan_broker(mut self, broker: Box<dyn emumee_core::broker::Client>) -> Self {
        self.broker = Some(broker);
        self
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Deny;
    impl emumee_core::broker::Client for Deny {
        fn call(
            &mut self,
            _: emumee_core::broker::Operation,
        ) -> std::result::Result<emumee_core::broker::Reply, String> {
            Err("No network allowed in source control".into())
        }
    }
    #[test]
    fn supplied_bytes_and_installed_values_determine_actual_guest_results() {
        use emumee_core::{
            analysis_plan::Arch,
            plan_runtime::{Case, Request},
        };
        for arch in [Arch::X86, Arch::X64] {
            for case in [Case::NativeA, Case::NativeB, Case::Kernel17, Case::Kernel19] {
                let (request, g) = Request::generated(
                    case,
                    arch,
                    "20261018T120000Z-00000001".into(),
                    "2026-10-18T12:00:00Z".into(),
                )
                .unwrap();
                let prepared = PreparedAnalysis::prepare(
                    &serde_json::to_vec(&request).unwrap(),
                    &g.plan,
                    g.inputs,
                    g.persona,
                )
                .unwrap();
                let execution = execute(&prepared, Box::new(Deny)).unwrap();
                assert_eq!(
                    execution.completion_reason,
                    "entry_return",
                    "{arch:?}/{case:?}: error={:?}, pc={:#x}, instructions={}, tail={}, apis={}",
                    execution.error,
                    execution.final_pc,
                    execution.instruction_count,
                    serde_json::to_string(&execution.instruction_tail).unwrap(),
                    serde_json::to_string(&execution.api_events).unwrap()
                );
                assert_eq!(
                    execution.guest_entry_return,
                    case.expected_return(),
                    "{arch:?}/{case:?}"
                );
                assert_eq!(
                    execution.configuration.unwrap().version,
                    "emumee-closed-plan-modeled-v1"
                );
            }
        }
    }
    #[test]
    fn closed_fault_guests_stop_by_real_timeout_or_publication_guard_and_checkpoint_has_actual_bytes()
     {
        use emumee_core::{analysis_plan::Arch, plan_runtime::Fault};
        for arch in [Arch::X86, Arch::X64] {
            for fault in [
                Fault::GuestTimeout,
                Fault::Reconfigure,
                Fault::CrashAfterCheckpoint,
            ] {
                let (request, g) = emumee_core::plan_runtime::Request::generated_fault(
                    fault.case(),
                    fault,
                    arch,
                    "20261019T120000Z-00000001".into(),
                    "2026-10-19T12:00:00Z".into(),
                )
                .unwrap();
                let prepared = PreparedAnalysis::prepare(
                    &serde_json::to_vec(&request).unwrap(),
                    &g.plan,
                    g.inputs,
                    g.persona,
                )
                .unwrap();
                let actual = execute(&prepared, Box::new(Deny)).unwrap();
                if fault == Fault::GuestTimeout {
                    assert_eq!(actual.completion_reason, "timeout");
                    assert!(
                        actual.instruction_count > 0 && actual.instruction_count < 1_000_000_000
                    );
                    assert!(actual.guest_entry_return.is_none());
                } else if fault == Fault::Reconfigure {
                    assert_eq!(actual.completion_reason, "error");
                    assert_eq!(actual.instruction_count, 1);
                    assert!(actual.guest_entry_return.is_none());
                    assert!(
                        actual
                            .error
                            .as_ref()
                            .unwrap()
                            .contains("cannot change after native publication")
                    );
                    let evidence = actual.closed_plan_fault.unwrap();
                    assert_eq!(evidence["before"], evidence["after"]);
                    assert_eq!(evidence["refused"], true);
                } else {
                    assert_eq!(actual.completion_reason, "entry_return");
                    assert_eq!(
                        actual.guest_entry_return,
                        Some(u32::from_le_bytes(*b"RUST") as u64)
                    );
                    assert_eq!(actual.artifacts.len(), 1);
                    assert_eq!(actual.artifacts[0].data, b"RUST");
                }
            }
        }
    }
}
