//! Parent orchestration for two distinct offline AppContainers and pinned RPC.
use super::worker::{save_new, verified_bundle, verify_artifacts};
use anyhow::{Context, Result, ensure};
use emumee_core::broker::{Config, OfflineHttp, Probe};
use emumee_platform::windows::{
    ContainedChild, OfflineProfile, OutputLimits, RecoverySession, WorkerJob, create_pinned,
    inspect_output, read_regular,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    time::{Duration, Instant},
};

pub(crate) fn wait_ready(child: &ContainedChild, path: &Path, root: &Path) -> Result<()> {
    let started = Instant::now();
    loop {
        ensure!(child.poll()?.is_none(), "Broker exited before ready");
        // Creation may be observed before the writer finishes. No client
        // starts until an entire bounded containment witness validates.
        if let Some(state) = read_regular(path, 4096, Some(root))
            .ok()
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
        {
            ensure!(
                state["app_container"] == true
                    && state["job_object"] == true
                    && state["child_process_blocked"] == true
                    && state["network_capabilities"] == 0,
                "Broker containment failure"
            );
            return Ok(());
        }
        ensure!(
            started.elapsed() < Duration::from_secs(5),
            "Broker readiness timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
pub(crate) fn pinned_new(path: &Path, data: &[u8]) -> Result<File> {
    let mut file = create_pinned(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(file)
}
pub fn fixture(
    root: &Path,
    probe: Probe,
    architecture: emumee_core::pe::Architecture,
) -> Result<Value> {
    session(root, probe, architecture, None)
}
pub(crate) fn installed_plan(
    root: &Path,
    case: emumee_core::plan_runtime::Case,
    architecture: emumee_core::pe::Architecture,
) -> Result<Value> {
    session(
        root,
        Probe::Normal,
        architecture,
        Some((case, emumee_core::plan_runtime::Fault::None)),
    )
}
pub(crate) fn installed_plan_fault(
    root: &Path,
    fault: emumee_core::plan_runtime::Fault,
    architecture: emumee_core::pe::Architecture,
) -> Result<Value> {
    ensure!(!fault.is_none(), "A fixed closed plan fault is required");
    session(
        root,
        Probe::Normal,
        architecture,
        Some((fault.case(), fault)),
    )
}

fn session(
    root: &Path,
    probe: Probe,
    architecture: emumee_core::pe::Architecture,
    plan_case: Option<(
        emumee_core::plan_runtime::Case,
        emumee_core::plan_runtime::Fault,
    )>,
) -> Result<Value> {
    let verified = verified_bundle()?;
    let executable = verified.path.join("emumee-worker.exe");
    let root = std::path::absolute(root)?;
    if plan_case.is_some() {
        let parent = root
            .parent()
            .context("Closed plan output parent absent")?
            .canonicalize()?;
        let destination = parent.join(root.file_name().context("Closed plan output name absent")?);
        ensure!(
            !destination.starts_with(&verified.path) && !verified.path.starts_with(&destination),
            "Closed plan output must be outside the frozen bundle"
        );
    }
    std::fs::create_dir(&root).context("Broker fixture root must be new")?;
    for name in ["control", "ipc", "private", "broker", "worker"] {
        std::fs::create_dir(root.join(name))?;
    }
    let mut cleanup_plan = RecoverySession::begin(&verified.path, &root)?;
    let installed = if let Some((case, fault)) = plan_case {
        use emumee_core::{
            analysis_plan::Arch,
            plan_runtime::{PreparedAnalysis, Request},
        };
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let (id, stamp) = emumee_core::analysis_fixture::identity(seconds, std::process::id())
            .map_err(anyhow::Error::msg)?;
        let arch = if architecture == emumee_core::pe::Architecture::X64 {
            Arch::X64
        } else {
            Arch::X86
        };
        let (request, g) =
            Request::generated_fault(case, fault, arch, id, stamp).map_err(anyhow::Error::msg)?;
        let raw = serde_json::to_vec(&request)?;
        let prepared = PreparedAnalysis::prepare(&raw, &g.plan, g.inputs, g.persona.clone())
            .map_err(anyhow::Error::msg)?;
        std::fs::create_dir(root.join("control/inputs"))?;
        // Private fixture slots are commitments, never granted to the worker.
        let public = prepared
            .request()
            .generated_inputs()
            .map_err(anyhow::Error::msg)?;
        for (index, (spec, bytes)) in prepared
            .spec()
            .inputs
            .iter()
            .zip(&public.inputs)
            .enumerate()
        {
            if !spec
                .roles
                .contains(&emumee_core::analysis_plan::InputRole::OfflineFixtures)
            {
                save_new(
                    &root.join("control/inputs").join(format!("{index:04}.bin")),
                    bytes,
                )?;
            }
        }
        save_new(&root.join("control/request.json"), &raw)?;
        save_new(&root.join("control/plan.json"), &public.plan)?;
        save_new(&root.join("control/persona.json"), &public.persona)?;
        Some((prepared, raw, public.fixtures))
    } else {
        None
    };
    let limits = if installed.is_some() {
        OutputLimits {
            max_bytes: emumee_core::plan_runtime::MAX_OUTPUT,
            max_entries: 22000,
            max_directories: 64,
            max_depth: 40,
        }
    } else {
        OutputLimits::default()
    };
    let fixture_raw = if let Some((_, _, raw)) = &installed {
        raw.clone()
    } else {
        serde_json::to_vec(&emumee_core::fixtures::http::document(probe)?)?
    };
    let _fixture_document = pinned_new(&root.join("private/http-fixtures.json"), &fixture_raw)?;
    let config = Config {
        schema: 4,
        fixture_document_sha256: (probe.http()
            || probe.binary()
            || probe.winhttp().is_some()
            || probe.internet().is_some())
        .then(|| format!("{:x}", Sha256::digest(&fixture_raw))),
        cleanup_plan: cleanup_plan
            .path()
            .to_str()
            .context("Cleanup plan path is not Unicode")?
            .to_owned(),
        probe,
        architecture: if architecture == emumee_core::pe::Architecture::X64 {
            "x64"
        } else {
            "x86"
        }
        .into(),
        fixture: OfflineHttp {
            url: "https://fixture.invalid/payload".into(),
            status: 200,
            body: b"RUST BROKER".to_vec(),
        },
    };
    let raw = if let Some((prepared, _, _)) = &installed {
        serde_json::to_vec_pretty(&emumee_core::plan_runtime::BrokerSession::new(
            prepared,
            config.cleanup_plan.clone(),
        ))?
    } else {
        serde_json::to_vec_pretty(&config)?
    };
    let digest = format!("{:x}", Sha256::digest(&raw));
    let _config = pinned_new(&root.join("control/config.json"), &raw)?;
    if installed.is_some() {
        super::plan_controller::verify_staged(&root)?;
    }
    let _requests = pinned_new(&root.join("ipc/requests.bin"), b"")?;
    let _responses = pinned_new(&root.join("ipc/responses.bin"), b"")?;
    let mut journal = pinned_new(&root.join("private/network-broker.journal"), b"")?;
    let broker_job = WorkerJob::new_tracked(256, &mut cleanup_plan)?;
    let worker_job = WorkerJob::new_tracked(
        if installed.is_some() { 1024 } else { 256 },
        &mut cleanup_plan,
    )?;
    let mut broker_profile = OfflineProfile::new_tracked(&mut cleanup_plan)?;
    let mut worker_profile = OfflineProfile::new_tracked(&mut cleanup_plan)?;
    let mut grants = Vec::new();
    let mut broker = None;
    let mut worker = None;
    let run = (|| -> Result<(String, u32, u32)> {
        grants.push(broker_profile.grant_tracked(&verified.path, false, &mut cleanup_plan)?);
        grants.push(worker_profile.grant_tracked(&verified.path, false, &mut cleanup_plan)?);
        if installed.is_some() {
            // Broker may inspect only its closed session commitments. The
            // guest target/persona and other staged slots stay worker-only.
            grants.push(
                broker_profile.grant_traverse_tracked(&root.join("control"), &mut cleanup_plan)?,
            );
            for name in ["config.json", "request.json", "plan.json"] {
                grants.push(broker_profile.grant_tracked(
                    &root.join("control").join(name),
                    false,
                    &mut cleanup_plan,
                )?);
            }
        } else {
            grants.push(broker_profile.grant_tracked(
                &root.join("control"),
                false,
                &mut cleanup_plan,
            )?);
        }
        grants.push(worker_profile.grant_tracked(
            &root.join("control"),
            false,
            &mut cleanup_plan,
        )?);
        grants.push(broker_profile.grant_tracked(&root.join("ipc"), false, &mut cleanup_plan)?);
        grants.push(worker_profile.grant_tracked(&root.join("ipc"), false, &mut cleanup_plan)?);
        grants.push(
            worker_profile
                .grant_append_tracked(&root.join("ipc/requests.bin"), &mut cleanup_plan)?,
        );
        grants.push(
            broker_profile
                .grant_append_tracked(&root.join("ipc/responses.bin"), &mut cleanup_plan)?,
        );
        grants.push(broker_profile.grant_tracked(
            &root.join("private"),
            false,
            &mut cleanup_plan,
        )?);
        grants.push(broker_profile.grant_tracked(
            &root.join("private/network-broker.journal"),
            true,
            &mut cleanup_plan,
        )?);
        grants.push(broker_profile.grant_tracked(&root.join("broker"), true, &mut cleanup_plan)?);
        grants.push(worker_profile.grant_tracked(&root.join("worker"), true, &mut cleanup_plan)?);
        broker = Some(broker_profile.spawn(
            &executable,
            &[
                OsString::from(if installed.is_some() {
                    "--plan-broker-server"
                } else {
                    "--broker-server"
                }),
                root.as_os_str().to_owned(),
                OsString::from(&digest),
            ],
            &root.join("broker"),
            &broker_job,
        )?);
        let server = broker.as_ref().unwrap();
        wait_ready(
            server,
            &root.join("broker/broker-ready.json"),
            &root.join("broker"),
        )?;
        worker = Some(
            worker_profile.spawn(
                &executable,
                &[
                    OsString::from(if installed.is_some() {
                        "--plan-worker"
                    } else {
                        "--broker-client"
                    }),
                    root.as_os_str().to_owned(),
                    OsString::from(
                        installed
                            .as_ref()
                            .map(|(p, _, _)| p.request_sha256())
                            .unwrap_or(&digest),
                    ),
                ],
                &root.join("worker"),
                &worker_job,
            )?,
        );
        let client = worker.as_ref().unwrap();
        let plan_fault = installed
            .as_ref()
            .map(|(p, _, _)| p.request().fault)
            .unwrap_or_default();
        if matches!(probe, Probe::ControllerCrash | Probe::ControllerPartial)
            || plan_fault.controller_exit()
        {
            let ready = root.join(if installed.is_some() {
                "worker/worker-ready.json"
            } else {
                "worker/client-ready.json"
            });
            let started = Instant::now();
            loop {
                if read_regular(&ready, 4096, Some(&root.join("worker")))
                    .ok()
                    .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
                    .is_some_and(|state| state["containment"]["app_container"] == true)
                {
                    break;
                }
                ensure!(
                    server.poll()?.is_none()
                        && client.poll()?.is_none()
                        && started.elapsed() < Duration::from_secs(5),
                    "Crash fixture roles did not become ready"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            if matches!(probe, Probe::ControllerPartial)
                || plan_fault == emumee_core::plan_runtime::Fault::ControllerPartial
            {
                cleanup_plan.torn_intent_for_fixture()?;
            }
            save_new(
                &root.join("controller-ready.json"),
                &serde_json::to_vec_pretty(
                    &json!({"controller_pid":std::process::id(),"broker_pid":server.id(),"worker_pid":client.id(),"scope":"Owned offline controller-termination qualification fixture"}),
                )?,
            )?;
            std::process::exit(27);
        }
        let started = Instant::now();
        let mut last_scan = Instant::now() - Duration::from_secs(1);
        loop {
            if last_scan.elapsed() >= Duration::from_millis(250) {
                inspect_output(&root, &[], limits)?;
                last_scan = Instant::now();
            }
            let server_exit = server.poll()?;
            let client_exit = client.poll()?;
            if let Some(exit) = server_exit.filter(|exit| *exit != 0) {
                return Ok(("broker_failed".into(), client.terminate()?, exit));
            }
            if let Some(exit) = client_exit.filter(|exit| *exit != 0) {
                if exit == 41
                    && plan_fault == emumee_core::plan_runtime::Fault::CrashAfterCheckpoint
                {
                    // The worker received the real Close reply before saving the
                    // checkpoint. Allow only this fixed fixture's already-closing
                    // broker a bounded natural process teardown; otherwise stop it.
                    let closing = Instant::now();
                    while server.poll()?.is_none() && closing.elapsed() < Duration::from_secs(1) {
                        inspect_output(&root, &[], limits)?;
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                return Ok(("worker_failed".into(), exit, server.terminate()?));
            }
            if let (Some(server_exit), Some(client_exit)) = (server_exit, client_exit) {
                inspect_output(&root, &[], limits)?;
                return Ok(("exited".into(), client_exit, server_exit));
            }
            ensure!(
                started.elapsed()
                    < Duration::from_millis(
                        installed
                            .as_ref()
                            .map(|(p, _, _)| p.request().fault.worker_deadline_ms())
                            .unwrap_or(10000)
                    ),
                "Broker session exceeded deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    // Stop both roles before changing any permissions, on all error paths.
    let worker_stop = worker.as_ref().map(ContainedChild::terminate).transpose();
    let broker_stop = broker.as_ref().map(ContainedChild::terminate).transpose();
    let worker_stopped = worker_stop?;
    let broker_stopped = broker_stop?;
    let mut cleanup_errors = Vec::new();
    for grant in grants.iter_mut().rev() {
        if let Err(error) = grant.restore() {
            cleanup_errors.push(format!("{error:#}"));
        }
    }
    if let Err(error) = worker_profile.close() {
        cleanup_errors.push(format!("{error:#}"));
    }
    if let Err(error) = broker_profile.close() {
        cleanup_errors.push(format!("{error:#}"));
    }
    ensure!(
        cleanup_errors.is_empty(),
        "Broker cleanup failed: {cleanup_errors:?}"
    );
    cleanup_plan.finish()?;
    journal.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    (&journal)
        .take(emumee_core::broker_journal::MAX_JOURNAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let recovery = emumee_core::broker_journal::recover(&bytes)?;
    save_new(
        &root.join("network-broker-recovery.json"),
        &serde_json::to_vec_pretty(&recovery)?,
    )?;
    let (reason, worker_exit, broker_exit) = match run {
        Ok(result) => result,
        Err(error) => (
            format!("session_error: {error:#}"),
            worker_stopped.unwrap_or(0),
            broker_stopped.unwrap_or(0),
        ),
    };
    let worker_result = read_regular(
        &root.join(if installed.is_some() {
            "worker/plan-result.json"
        } else {
            "worker/broker-result.json"
        }),
        5 * 1024 * 1024,
        Some(&root.join("worker")),
    )
    .ok()
    .map(|raw| serde_json::from_slice::<Value>(&raw))
    .transpose()?;
    if let Some(result) = &worker_result {
        if result.get("execution").is_some() {
            verify_artifacts(&root.join("worker"), &result["execution"]["artifacts"])?;
        }
    }
    let qualified = reason == "exited"
        && worker_exit == 0
        && broker_exit == 0
        && recovery.closed
        && worker_result.as_ref().is_some_and(|result| {
            result["request_sha256"]
                == installed
                    .as_ref()
                    .map(|(p, _, _)| p.request_sha256())
                    .unwrap_or(&digest)
                && result["containment"]["app_container"] == true
                && result["containment"]["job_object"] == true
                && result["containment"]["child_process_blocked"] == true
                && result["containment"]["network_capabilities"] == 0
                && (result.get("execution").is_none()
                    || result["execution"]["completion_reason"] == "entry_return")
        });
    let mut result = json!({"schema":1,"source_tree_sha256":verified.receipt["source_tree_sha256"],"controller_recovery":verified.recovery,"request_sha256":digest,"reason":reason,"worker_exit":worker_exit,"broker_exit":broker_exit,"cleanup":"restored","qualified":qualified,"journal":recovery,"worker_result":worker_result,"scope":if installed.is_some(){"Closed actual staged plan inputs with distinct offline broker; full tool/general run still gated"}else{"Two distinct offline AppContainers; fixed pinned IPC and private broker journal; generated boundary fixture."}});
    if let Some((prepared, _, _)) = &installed {
        result["boundary_qualified"] = json!(qualified);
        result["fault"] = serde_json::to_value(prepared.request().fault)?;
        result["qualified"] = json!(false);
        result["bundle_receipt"] = verified.receipt.clone();
        result["job_profile"] = json!({"worker_memory_mb":1024,"broker_memory_mb":256,"output_bytes":emumee_core::plan_runtime::MAX_OUTPUT,"scope":"Explicit closed-plan cap, not the Legacy512 fixture job profile or arbitrary worker admission"});
    }
    save_new(
        &root.join("broker-session.json"),
        &serde_json::to_vec_pretty(&result)?,
    )?;
    if qualified && installed.is_none() {
        save_new(
            &root.join("manifest.json"),
            &serde_json::to_vec_pretty(&result)?,
        )?;
    }
    Ok(result)
}
