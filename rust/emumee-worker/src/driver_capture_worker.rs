//! Fixed Driver128 generated capture worker. Never accepts arbitrary input.
use super::save_new;
use anyhow::{Result, ensure};
use emumee_core::{
    artifacts::{ArtifactCatalog, ArtifactKind, Observation},
    capture_profile::CaptureProfile,
    driver_capture_fixture::{Case, Fault, Request},
    driver_capture_reports::{self as reports, Binding, Mode, Stop},
    report_bundle::{bounded_json, digest},
};
use emumee_platform::windows::{prepare_worker, read_regular};
use serde_json::{Value, json};
use std::{fs::OpenOptions, io::Write, path::Path};
pub fn execute(root: &Path, request_hash: &str) -> Result<()> {
    let root = std::path::absolute(root)?;
    let containment = prepare_worker()?;
    let witness = serde_json::to_vec(&containment)?;
    save_new(&root.join("worker-containment.json"), &witness)?;
    let result = (|| -> Result<()> {
        let raw = read_regular(&root.join("request.json"), 4096, Some(&root))?;
        ensure!(
            digest(&raw) == request_hash,
            "Driver128 request hash changed"
        );
        let request = Request::parse(&raw).map_err(anyhow::Error::msg)?;
        let input = read_regular(&root.join("input.bin"), 128 * 1024 * 1024, Some(&root))?;
        ensure!(
            input.len() == request.input_size && digest(&input) == request.input_sha256,
            "Driver128 fixed input hash/size changed"
        );
        save_new(
            &root.join("worker-ready.json"),
            &serde_json::to_vec(
                &json!({"profile":reports::PROFILE,"request_sha256":request_hash,"input_sha256":request.input_sha256,"job_memory_mib_required":2048}),
            )?,
        )?;
        let binding = Binding {
            request_sha256: request_hash.into(),
            input_sha256: request.input_sha256.clone(),
            input_bytes: input.len() as u64,
            recipe: serde_json::to_value(request.case)?.as_str().unwrap().into(),
            source_tree_sha256: env!("EMUMEE_BUILD_SOURCE_SHA256").into(),
            containment_sha256: digest(&witness),
        };
        let mut catalog = ArtifactCatalog::with_profile(CaptureProfile::Driver128V1);
        let mode;
        let execution: Value;
        if let Some(case) = request.case.runtime_case() {
            mode = Mode::GeneratedDriverCapture;
            drop(input);
            let mut result = emumee_engine::run_driver_runtime_fixture(case)?;
            execution = serde_json::to_value(&result)?;
            let retention = result
                .capture_runtime
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Runtime capture receipt missing"))?
                .retention_limit as usize;
            catalog = ArtifactCatalog::from_owned_parts(
                CaptureProfile::Driver128V1,
                std::mem::take(&mut result.artifacts),
                std::mem::take(&mut result.capture_summary),
                retention,
            )
            .map_err(anyhow::Error::msg)?;
        } else if request.case == Case::DriverEntry64 {
            mode = Mode::GeneratedDriverEntry;
            let result = emumee_engine::run_driver_capture_entry_fixture()?;
            execution = serde_json::to_value(result)?;
            drop(input);
        } else {
            mode = Mode::StaticGeneratedCapture;
            let stats;
            if request.case == Case::SingleOverflow {
                ensure!(
                    !catalog.add_owned_observations(
                        vec![0x53; 128 * 1024 * 1024 + 1],
                        vec![Observation {
                            kind: ArtifactKind::MemorySnapshot,
                            source: "synthetic_single_overflow".into(),
                            guest_path: String::new(),
                            context: None
                        }]
                    ),
                    "Driver128 single overflow unexpectedly retained"
                );
                stats =
                    json!({"scope":"Owned single-payload bound; oversized data was not retained"});
            } else if matches!(request.case, Case::Dedupe128 | Case::Total256Overflow) {
                let mut observations = vec![Observation {
                    kind: ArtifactKind::MemorySnapshot,
                    source: "synthetic_recipe_bytes".into(),
                    guest_path: String::new(),
                    context: None,
                }];
                if request.case == Case::Dedupe128 {
                    observations.push(Observation {
                        kind: ArtifactKind::MemorySnapshot,
                        source: "synthetic_recipe_alias".into(),
                        guest_path: String::new(),
                        context: None,
                    });
                }
                ensure!(
                    catalog.add_owned_observations(input, observations),
                    "Driver128 initial owned capture refused"
                );
                if request.case == Case::Total256Overflow {
                    ensure!(
                        catalog.add_owned_observations(
                            vec![0x53; 128 * 1024 * 1024],
                            vec![Observation {
                                kind: ArtifactKind::MemorySnapshot,
                                source: "synthetic_second_payload".into(),
                                guest_path: String::new(),
                                context: None
                            }]
                        ),
                        "Driver128 total boundary refused"
                    );
                    ensure!(
                        !catalog.add_owned_observations(
                            vec![0x54],
                            vec![Observation {
                                kind: ArtifactKind::MemorySnapshot,
                                source: "synthetic_total_overflow".into(),
                                guest_path: String::new(),
                                context: None
                            }]
                        ),
                        "Driver128 total overflow unexpectedly retained"
                    );
                }
                stats = json!({"scope":"Owned synthetic payload ownership/dedupe/total controls"});
            } else {
                let input = if request.case == Case::ScanOverflow {
                    vec![0u8; 128 * 1024 * 1024 + 1]
                } else {
                    input
                };
                let scan = if request.case.mapped() {
                    // Compiler-owned recipe is a complete mapped image;
                    // Origin::Memory alone is not layout authority.
                    let limits = CaptureProfile::Driver128V1.limits();
                    emumee_core::pe_carve::scan_owned_mapped_root(
                        input,
                        "synthetic_recipe",
                        None,
                        CaptureProfile::Driver128V1,
                        limits.scan,
                        limits.work,
                    )?
                } else {
                    emumee_core::pe_carve::scan_owned_with_profile(
                        input,
                        "synthetic_recipe",
                        false,
                        None,
                        CaptureProfile::Driver128V1,
                    )?
                };
                stats = serde_json::to_value(emumee_core::artifact_bridge::capture_scan_owned(
                    &mut catalog,
                    scan,
                    emumee_core::artifact_bridge::Origin::Memory,
                )?)?;
            }
            execution = json!({"completion_reason":"static_inspection","instruction_count":0,"guest_entry_return":null,"error":null,"capture":stats,"scope":"Compiler-owned generated static bytes only; no driver instructions executed"});
        }
        let bundle = reports::build(
            &request.run_id,
            &binding,
            mode,
            &execution,
            Stop::Normal,
            false,
            &catalog,
        )?;
        std::fs::create_dir(root.join("artifacts"))?;
        for (name, bytes) in &bundle.payloads {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(root.join("artifacts").join(name))?;
            for chunk in bytes.chunks(8 * 1024 * 1024) {
                file.write_all(chunk)?;
            }
            file.sync_all()?;
        }
        save_new(&root.join("engine-report.json"), &bundle.engine)?;
        save_new(&root.join("network-broker.json"), &bundle.network)?;
        save_new(&root.join("artifacts/manifest.json"), &bundle.manifest)?;
        save_new(&root.join("worker-summary.json"), &bundle.summary)?;
        if request.fault == Fault::CrashBeforeCheckpoint {
            std::process::exit(23)
        }
        save_new(&root.join("artifact-checkpoint.json"), &bundle.checkpoint)?;
        match request.fault {
            Fault::CrashAfterCheckpoint => std::process::exit(23),
            Fault::TimeoutAfterCheckpoint => {
                std::thread::sleep(std::time::Duration::from_secs(30));
                anyhow::bail!("Driver checkpoint timeout control did not stop")
            }
            Fault::TamperPayload => {
                let name = bundle.payloads[0].0;
                replace(&root.join("artifacts").join(name), b"broken")?;
            }
            Fault::TamperEngine => {
                let mut bytes = bundle.engine.clone();
                bytes.push(b' ');
                replace(&root.join("engine-report.json"), &bytes)?;
            }
            Fault::ProfileDowngrade => {
                let mut value: Value = serde_json::from_slice(&bundle.summary)?;
                value["profile"] = json!("legacy32_v1");
                replace(
                    &root.join("worker-summary.json"),
                    &bounded_json(&value, 5 * 1024 * 1024)?,
                )?;
            }
            Fault::TamperProvenance => {
                let mut value: Value = serde_json::from_slice(&bundle.summary)?;
                value["artifacts"][0]["observations"][0]["source"] = json!("forged");
                replace(
                    &root.join("worker-summary.json"),
                    &bounded_json(&value, 5 * 1024 * 1024)?,
                )?;
            }
            _ => {}
        }
        save_new(
            &root.join("driver-result.json"),
            &serde_json::to_vec(
                &json!({"schema":1,"profile":reports::PROFILE,"binding":binding,"summary_sha256":digest(&read_regular(&root.join("worker-summary.json"),5*1024*1024,Some(&root))?)}),
            )?,
        )?;
        Ok(())
    })();
    if let Err(error) = &result {
        let text = format!("{error:#}").chars().take(8192).collect::<String>();
        let _ = save_new(&root.join("worker-error.txt"), text.as_bytes());
    }
    result
}
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
