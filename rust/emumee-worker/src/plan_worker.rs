//! Compiler-owned plan installation role, executing actual staged public bytes.
use super::save_new;
use anyhow::{Context, Result, ensure};
use emumee_core::{
    artifacts::ArtifactCatalog,
    plan_runtime::{Fault, PreparedAnalysis, Request},
    report_bundle::{self, Input, NetworkCoverage, Profile, Termination},
};
use emumee_platform::windows::{prepare_worker, read_regular};
use serde_json::json;
use std::{fs::File, path::Path};
pub fn execute(root: &Path, expected: &str) -> Result<()> {
    let containment = prepare_worker()?;
    let root = std::path::absolute(root)?;
    let control = root.join("control");
    let output = root.join("worker");
    let result = (|| -> Result<()> {
        let raw = read_regular(&control.join("request.json"), 4096, Some(&control))?;
        ensure!(
            report_bundle::digest(&raw) == expected,
            "Plan request transport changed"
        );
        let request = Request::parse(&raw).map_err(anyhow::Error::msg)?;
        let plan = read_regular(
            &control.join("plan.json"),
            emumee_core::analysis_plan::MAX_PLAN_BYTES,
            Some(&control),
        )?;
        let persona = read_regular(
            &control.join("persona.json"),
            emumee_core::analysis_plan::MAX_PLAN_BYTES,
            Some(&control),
        )?;
        let spec = emumee_core::analysis_plan::PlanSpec::decode(&plan)?;
        ensure!(spec.inputs.len() <= 4, "Closed plan input count");
        let mut inputs = Vec::new();
        for (index, input) in spec.inputs.iter().enumerate() {
            if input
                .roles
                .contains(&emumee_core::analysis_plan::InputRole::OfflineFixtures)
            {
                inputs.push(None)
            } else {
                ensure!(
                    input.size <= emumee_core::plan_runtime::MAX_INPUT as u64,
                    "Closed input bound"
                );
                inputs.push(Some(read_regular(
                    &control.join("inputs").join(format!("{index:04}.bin")),
                    input.size as usize,
                    Some(&control),
                )?));
            }
        }
        let prepared = PreparedAnalysis::prepare_worker(&raw, &plan, inputs, persona)
            .map_err(anyhow::Error::msg)?;
        let fixture_denied = File::open(root.join("private/http-fixtures.json"))
            .err()
            .is_some_and(|e| e.raw_os_error() == Some(5));
        let journal_denied = File::open(root.join("private/network-broker.journal"))
            .err()
            .is_some_and(|e| e.raw_os_error() == Some(5));
        ensure!(
            fixture_denied && journal_denied,
            "Plan worker can read private broker bytes"
        );
        let broker_raw = read_regular(&control.join("config.json"), 4096, Some(&control))?;
        let broker_config = emumee_core::plan_runtime::BrokerSession::parse(&broker_raw, &raw)
            .map_err(anyhow::Error::msg)?;
        let cleanup_denied = File::open(&broker_config.cleanup_plan)
            .err()
            .is_some_and(|e| e.raw_os_error() == Some(5));
        ensure!(
            cleanup_denied,
            "Plan worker can inspect private controller cleanup intent"
        );
        let witness = serde_json::to_vec(&containment)?;
        save_new(&output.join("worker-containment.json"), &witness)?;
        let binding = prepared.receipt();
        save_new(
            &output.join("worker-ready.json"),
            &serde_json::to_vec(
                &json!({"role":"closed_plan_worker","request_sha256":expected,"installation":binding,"containment":containment,"private_fixture_denied":fixture_denied,"private_journal_denied":journal_denied,"cleanup_plan_read_denied":cleanup_denied}),
            )?,
        )?;
        if request.fault.controller_exit() {
            std::thread::sleep(std::time::Duration::from_secs(60));
            anyhow::bail!("Controller termination fixture was not stopped");
        }
        if request.fault == Fault::OutputDirectories {
            for index in 0..65 {
                std::fs::create_dir(output.join(format!("owned-dir-{index:03}")))?;
            }
            std::thread::sleep(std::time::Duration::from_secs(60));
            anyhow::bail!("Output directory watchdog fixture was not stopped");
        }
        let (rpc, close) = super::broker::plan_connection(&root)?;
        let native = if request.case.static_only() {
            None
        } else {
            Some(emumee_engine::plan_runtime::execute(&prepared, rpc))
        };
        let close_result = close.close();
        let native = native.transpose()?;
        close_result?;
        let mut static_catalog = ArtifactCatalog::with_retention_budget(
            emumee_core::capture_profile::CaptureProfile::Legacy32V1,
            prepared.spec().capture.retained_bytes as usize,
        )
        .context("Static capture budget")?;
        let (sample, execution, network) = if let Some(native) = &native {
            (
                serde_json::to_value(
                    emumee_core::pe::PeImage::parse(prepared.input(), "owned-generated.pe")?.sample,
                )?,
                serde_json::to_value(native)?,
                serde_json::to_value(&native.network)?,
            )
        } else {
            let inspection = emumee_core::msi::inspect(prepared.input())?;
            for stream in &inspection.streams {
                emumee_core::artifact_bridge::capture_container_stream(
                    &mut static_catalog,
                    stream,
                )?;
            }
            ensure!(
                emumee_core::artifact_bridge::merge_container_omissions(
                    &mut static_catalog,
                    &inspection
                ),
                "Static omissions failed"
            );
            (
                json!({"name":"owned.msi","kind":"msi","sha256":report_bundle::digest(prepared.input()),"size":prepared.input().len(),"managed":false}),
                json!({"backend":"rust/static-msi","completion_reason":"static_inspection","instruction_count":0,"guest_entry_return":null,"error":null,"inspection":inspection,"artifacts":static_catalog.items,"capture_summary":static_catalog.summary}),
                json!({"events":[]}),
            )
        };
        let (artifacts, omissions) = if let Some(native) = &native {
            (&native.artifacts, &native.capture_summary)
        } else {
            (&static_catalog.items, &static_catalog.summary)
        };
        let manifest = json!({"schema":1,"role":"closed_plan_installation","request_sha256":expected,"input_sha256":report_bundle::digest(prepared.input()),"input_size":prepared.input().len(),"case":request.case,"architecture":request.architecture,"source_tree_sha256":env!("EMUMEE_BUILD_SOURCE_SHA256"),"containment_sha256":report_bundle::digest(&witness),"installation":binding});
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let finished = emumee_core::analysis_fixture::identity(seconds, 0)
            .map_err(anyhow::Error::msg)?
            .1;
        let bundle = report_bundle::build(Input {
            run_id: &request.run_id,
            started_at: &request.started_at,
            finished_at: &finished,
            sample: &sample,
            execution: &execution,
            execution_mode: if request.case.kernel() {
                "kernel"
            } else {
                "user"
            },
            manifest: &manifest,
            network: &network,
            network_coverage: NetworkCoverage::ModelOnly,
            termination: Termination::Normal,
            checkpoint_recovered: false,
            profile: Profile::LegacyV1,
            artifacts,
            omissions,
        })?;
        std::fs::create_dir(output.join("artifacts"))?;
        for payload in &bundle.payloads {
            save_new(
                &output.join("artifacts").join(&payload.filename),
                payload.bytes,
            )?;
        }
        for (name, bytes) in [
            ("worker-summary.json", &bundle.summary),
            ("engine-report.json", &bundle.engine),
            ("network-broker.json", &bundle.network),
            ("artifacts/manifest.json", &bundle.manifest),
            ("artifact-checkpoint.json", &bundle.checkpoint),
        ] {
            save_new(&output.join(name), bytes)?;
        }
        let receipt = serde_json::to_vec(
            &json!({"schema":1,"role":"closed_plan_worker","request_sha256":expected,"containment":containment,"installation":binding,"private_fixture_denied":fixture_denied,"private_journal_denied":journal_denied,"summary_sha256":report_bundle::digest(&bundle.summary),"engine_sha256":report_bundle::digest(&bundle.engine),"network_sha256":report_bundle::digest(&bundle.network),"manifest_sha256":report_bundle::digest(&bundle.manifest)}),
        )?;
        if request.fault.checkpoint() {
            save_new(&output.join("plan-checkpoint.json"), &receipt)?;
            match request.fault {
                Fault::CrashAfterCheckpoint => std::process::exit(41),
                Fault::TimeoutAfterCheckpoint => {
                    std::thread::sleep(std::time::Duration::from_secs(60));
                    anyhow::bail!("Checkpoint timeout fixture was not stopped");
                }
                _ => unreachable!(),
            }
        }
        save_new(&output.join("plan-result.json"), &receipt)?;
        Ok(())
    })();
    if let Err(error) = &result {
        let _ = save_new(
            &output.join("worker-error.txt"),
            format!("{error:#}")
                .chars()
                .take(8192)
                .collect::<String>()
                .as_bytes(),
        );
    }
    result.context("Closed plan worker failed")
}
