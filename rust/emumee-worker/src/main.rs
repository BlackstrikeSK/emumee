//! Restricted worker entry point; submitted drivers require the offline role.
use anyhow::{Context, Result, ensure};
use emumee_core::{
    pe::Architecture,
    protocol::{BoundaryProbe, FixtureRequest},
};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};
#[cfg(windows)]
mod analysis_fixture;
#[cfg(windows)]
mod broker;
#[cfg(windows)]
mod driver_capture_worker;
#[cfg(windows)]
mod driver_input_worker;
#[cfg(windows)]
mod general_boundary_worker;
#[cfg(windows)]
mod general_plan_worker;
#[cfg(windows)]
mod msi_static;

fn save_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}
fn save_artifacts(root: &Path, artifacts: &[emumee_core::artifacts::Artifact]) -> Result<()> {
    if artifacts.is_empty() {
        return Ok(());
    }
    let directory = root.join("artifacts");
    std::fs::create_dir(&directory)?;
    for artifact in artifacts {
        ensure!(
            artifact.filename == format!("{}.bin", artifact.sha256),
            "Invalid generated artifact filename"
        );
        ensure!(
            format!("{:x}", Sha256::digest(&artifact.data)) == artifact.sha256,
            "Captured artifact changed"
        );
        save_new(&directory.join(&artifact.filename), &artifact.data)?;
    }
    Ok(())
}
/// Fixed harmless faults for parent watchdog qualification. Runs only after
/// containment and request-hash verification; never invokes sample code.
fn boundary_probe(root: &Path, probe: BoundaryProbe) -> Result<()> {
    match probe {
        BoundaryProbe::Normal => return Ok(()),
        BoundaryProbe::AbruptExit => std::process::exit(23),
        BoundaryProbe::Timeout => (),
        BoundaryProbe::OutputBytes | BoundaryProbe::FastOutput => {
            save_new(&root.join("quota.bin"), &vec![0x52; 2 * 1024 * 1024])?;
            if matches!(probe, BoundaryProbe::FastOutput) {
                return Ok(());
            }
        }
        BoundaryProbe::OutputCount => {
            for index in 0..32 {
                save_new(&root.join(format!("quota-{index}.bin")), b"R")?;
            }
        }
        BoundaryProbe::OutputLink => {
            let carrier = root.join("carrier.bin");
            save_new(&carrier, b"R")?;
            std::fs::hard_link(carrier, root.join("linked.bin"))?;
        }
        BoundaryProbe::FileStream | BoundaryProbe::DirectoryStream => {
            let carrier = if matches!(probe, BoundaryProbe::FileStream) {
                let path = root.join("carrier.bin");
                save_new(&path, b"R")?;
                path
            } else {
                root.to_path_buf()
            };
            let mut name = carrier.as_os_str().to_owned();
            name.push(":quota_probe");
            save_new(&PathBuf::from(name), &vec![0x52; 2 * 1024 * 1024])?;
        }
    }
    std::thread::sleep(std::time::Duration::from_secs(10));
    anyhow::bail!("Boundary probe was not stopped by its parent")
}
#[cfg(windows)]
fn execute(root: &Path, expected: &str) -> Result<()> {
    use emumee_platform::windows::{prepare_worker, read_regular};
    let containment = prepare_worker()?;
    let root = std::path::absolute(root)?;
    let result = (|| -> Result<()> {
        let raw = read_regular(&root.join("request.json"), 4096, Some(&root))?;
        ensure!(
            format!("{:x}", Sha256::digest(&raw)) == expected,
            "Worker request hash changed"
        );
        let request: FixtureRequest = serde_json::from_slice(&raw)?;
        ensure!(request.schema == 1, "Unknown fixture request schema");
        if let Some(probe) = request.boundary_probe {
            save_new(
                &root.join("worker-ready.json"),
                &serde_json::to_vec_pretty(&containment)?,
            )?;
            boundary_probe(&root, probe)?;
        }
        let architecture = match request.architecture.as_str() {
            "x64" => Architecture::X64,
            "x86" => Architecture::X86,
            _ => anyhow::bail!("Invalid architecture"),
        };
        let execution = emumee_engine::run_fixture_kind(
            architecture,
            request.kind,
            request.iterations,
            request.max_instructions,
        )?;
        save_artifacts(&root, execution.artifacts())?;
        let report = serde_json::to_vec_pretty(
            &serde_json::json!({"schema":1,"request_sha256":expected,"containment":containment,"execution":execution,"scope":"Generated fixture in a dedicated Rust offline worker; not general sample execution."}),
        )?;
        ensure!(
            report.len() <= 5 * 1024 * 1024,
            "Fixture report exceeds 5MiB bound"
        );
        save_new(&root.join("fixture-result.json"), &report)?;
        Ok(())
    })();
    if let Err(error) = &result {
        let message = format!("{error:#}").chars().take(8192).collect::<String>();
        let _ = save_new(&root.join("worker-error.txt"), message.as_bytes());
    }
    result
}
fn main() {
    if let Err(error) = entry() {
        eprintln!("{error:#}");
        std::process::exit(2);
    }
}
fn entry() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let first = args
        .next()
        .context("Worker requires a run directory and request hash")?;
    if first == "--build-info" {
        ensure!(args.next().is_none(), "Unexpected build-info arguments");
        println!(
            "{}",
            serde_json::json!({"source_tree_sha256":env!("EMUMEE_BUILD_SOURCE_SHA256"),"role":"offline_worker","unicorn_version":"2.1.5"})
        );
        return Ok(());
    }
    if first == "--general-plan-verify" {
        let root = PathBuf::from(
            args.next()
                .context("General verify-only role requires a run root")?,
        );
        let expected = args
            .next()
            .context("General verify-only role requires a request digest")?;
        ensure!(
            args.next().is_none(),
            "Unexpected general verify-only role arguments"
        );
        #[cfg(windows)]
        {
            return general_plan_worker::execute(&root, &expected);
        }
        #[cfg(not(windows))]
        {
            let _ = (root, expected);
            anyhow::bail!("General verify-only worker requires Windows");
        }
    }
    if first == "--general-public-read-probe" || first == "--general-private-read-probe" {
        let root = PathBuf::from(
            args.next()
                .context("General boundary probe requires run root")?,
        );
        let expected = args
            .next()
            .context("General boundary probe requires transport digest")?;
        ensure!(
            args.next().is_none(),
            "Unexpected general boundary probe arguments"
        );
        #[cfg(windows)]
        {
            return if first == "--general-public-read-probe" {
                general_boundary_worker::public_probe(&root, &expected)
            } else {
                general_boundary_worker::private_probe(&root, &expected)
            };
        }
        #[cfg(not(windows))]
        {
            let _ = (root, expected);
            anyhow::bail!("General boundary probes require Windows");
        }
    }
    if first == "--general-rpc-client"
        || first == "--general-rpc-server"
        || first == "--general-driver128-broker"
    {
        let root = PathBuf::from(
            args.next()
                .context("General RPC role requires a run root")?,
        );
        let expected = args
            .next()
            .context("General RPC role requires a transport digest")?;
        let extra = args
            .next()
            .context("General RPC role requires a second binding")?;
        ensure!(
            args.next().is_none(),
            "Unexpected general RPC role arguments"
        );
        #[cfg(windows)]
        {
            let result = match first.as_str() {
                "--general-rpc-client" => {
                    general_boundary_worker::rpc_client(&root, &expected, &extra)
                }
                "--general-driver128-broker" => {
                    broker::general_driver128_server(&root, &expected, Path::new(&extra))
                }
                _ => broker::general_server(&root, &expected, Path::new(&extra)),
            };
            if let Err(error) = &result {
                if emumee_platform::windows::verify_containment().is_ok() {
                    let role = if first == "--general-rpc-client" {
                        "worker"
                    } else {
                        "broker"
                    };
                    let _ = save_new(
                        &root.join(role).join("role-error.txt"),
                        format!("{error:#}")
                            .chars()
                            .take(8192)
                            .collect::<String>()
                            .as_bytes(),
                    );
                }
            }
            return result;
        }
        #[cfg(not(windows))]
        {
            let _ = (root, expected, extra);
            anyhow::bail!("General RPC roles require Windows");
        }
    }
    if first == "--submitted-driver" {
        let root = PathBuf::from(
            args.next()
                .context("Submitted driver role requires a run root")?,
        );
        let expected = args
            .next()
            .context("Submitted driver role requires a request hash")?;
        ensure!(
            args.next().is_none(),
            "Unexpected submitted driver role arguments"
        );
        #[cfg(windows)]
        {
            return driver_input_worker::execute(&root, &expected);
        }
        #[cfg(not(windows))]
        {
            let _ = (root, expected);
            anyhow::bail!("Submitted driver worker requires Windows");
        }
    }
    if first == "--submitted-driver-broker" {
        let root = PathBuf::from(
            args.next()
                .context("Brokered submitted driver role requires a run root")?,
        );
        let expected = args
            .next()
            .context("Brokered submitted driver role requires a request hash")?;
        let claim = args
            .next()
            .context("Brokered submitted driver role requires a private claim hash")?;
        ensure!(
            args.next().is_none(),
            "Unexpected brokered submitted driver role arguments"
        );
        #[cfg(windows)]
        {
            return driver_input_worker::execute_brokered(&root, &expected, &claim);
        }
        #[cfg(not(windows))]
        {
            let _ = (root, expected, claim);
            anyhow::bail!("Brokered submitted driver worker requires Windows");
        }
    }
    if first == "--driver-capture-fixture" {
        let root = PathBuf::from(args.next().context("Driver128 role requires a run root")?);
        let expected = args
            .next()
            .context("Driver128 role requires a request hash")?;
        ensure!(args.next().is_none(), "Unexpected Driver128 role arguments");
        #[cfg(windows)]
        {
            return driver_capture_worker::execute(&root, &expected);
        }
        #[cfg(not(windows))]
        {
            let _ = (root, expected);
            anyhow::bail!("Driver128 worker requires Windows");
        }
    }
    if first == "--plan-worker" || first == "--plan-broker-server" {
        let root = PathBuf::from(args.next().context("Plan role requires a root")?);
        let hash = args
            .next()
            .context("Plan role requires a transport digest")?;
        ensure!(args.next().is_none(), "Unexpected plan role arguments");
        #[cfg(windows)]
        {
            let result = if first == "--plan-worker" {
                plan_worker::execute(&root, &hash)
            } else {
                broker::plan_server(&root, &hash)
            };
            if let Err(error) = &result {
                if emumee_platform::windows::verify_containment().is_ok() {
                    let role = if first == "--plan-worker" {
                        "worker"
                    } else {
                        "broker"
                    };
                    let _ = save_new(
                        &root.join(role).join("role-error.txt"),
                        format!("{error:#}")
                            .chars()
                            .take(8192)
                            .collect::<String>()
                            .as_bytes(),
                    );
                }
            }
            return result;
        }
        #[cfg(not(windows))]
        {
            let _ = (root, hash);
            anyhow::bail!("Closed plan roles require Windows");
        }
    }
    if first == "--analysis-fixture" {
        let root = PathBuf::from(args.next().context("Analysis role requires a run root")?);
        let expected = args
            .next()
            .context("Analysis role requires a request hash")?;
        ensure!(args.next().is_none(), "Unexpected analysis role arguments");
        #[cfg(windows)]
        {
            return analysis_fixture::execute(&root, &expected);
        }
        #[cfg(not(windows))]
        {
            let _ = (root, expected);
            anyhow::bail!("Generated analysis worker requires Windows");
        }
    }

    if first == "--msi-fixture" {
        let root = PathBuf::from(args.next().context("MSI role requires a run root")?);
        let expected = args.next().context("MSI role requires a request hash")?;
        ensure!(args.next().is_none(), "Unexpected MSI role arguments");
        #[cfg(windows)]
        {
            return msi_static::execute(&root, &expected);
        }
        #[cfg(not(windows))]
        {
            let _ = (root, expected);
            anyhow::bail!("Static MSI worker requires Windows");
        }
    }
    if first == "--broker-server" || first == "--broker-client" {
        let root = PathBuf::from(args.next().context("Broker role requires a run root")?);
        let expected = args
            .next()
            .context("Broker role requires a configuration hash")?;
        ensure!(args.next().is_none(), "Unexpected broker role arguments");
        #[cfg(windows)]
        {
            let result = if first == "--broker-server" {
                broker::server(&root, &expected)
            } else {
                broker::client(&root, &expected)
            };
            if let Err(error) = &result {
                if emumee_platform::windows::verify_containment().is_ok() {
                    let role = if first == "--broker-server" {
                        "broker"
                    } else {
                        "worker"
                    };
                    let message = format!("{error:#}").chars().take(8192).collect::<String>();
                    let _ = save_new(&root.join(role).join("role-error.txt"), message.as_bytes());
                }
            }
            return result;
        }
        #[cfg(not(windows))]
        {
            let _ = (root, expected);
            anyhow::bail!("Broker roles require Windows");
        }
    }
    let root = PathBuf::from(first);
    let expected = args.next().context("Request hash missing")?;
    ensure!(args.next().is_none(), "Unexpected worker arguments");
    #[cfg(windows)]
    {
        execute(&root, &expected)
    }
    #[cfg(not(windows))]
    {
        let _ = (root, expected);
        anyhow::bail!("Offline worker requires Windows")
    }
}

#[cfg(windows)]
mod plan_worker;
