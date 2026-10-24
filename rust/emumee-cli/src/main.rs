use anyhow::{Context, Result, bail};
use emumee_core::driver_input::InstructionWindow;
use emumee_core::pe::{Architecture, MAX_INPUT, PeImage};
use emumee_core::protocol::{BoundaryProbe, FixtureKind};
use std::{fs::File, io::Read, path::PathBuf};
#[cfg(windows)]
mod analysis_fixture;
mod batch_aggregate;
mod batch_inventory;
mod batch_log;
mod batch_report_map;
mod batch_sequence;
#[cfg(windows)]
mod broker;
#[cfg(windows)]
mod driver_capture_controller;
#[cfg(windows)]
mod driver_capture_reader;
#[cfg(windows)]
mod driver_input_controller;
#[cfg(windows)]
mod general_boundary_controller;
#[cfg(windows)]
mod general_execution_stage;
#[cfg(windows)]
mod general_intake_stage;
#[cfg(windows)]
mod general_plan_controller;
#[cfg(windows)]
mod general_rpc_controller;
#[cfg(windows)]
mod msi_fixture;
mod msi_reader;
mod msi_report;
mod plan_reader;
mod powershell_report;
mod powershell_source;
mod report_index;
mod report_reader;
mod worker;

fn bounded_input(path: &PathBuf) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)
        .with_context(|| format!("Cannot read {}", path.display()))?
        .take(MAX_INPUT as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > MAX_INPUT {
        bail!("Input exceeds128MiB");
    }
    Ok(data)
}

#[derive(Debug, PartialEq, Eq)]
struct SubmittedOptions {
    service: String,
    max_instructions: u64,
    timeout_us: u64,
    kernel_code_reference: Option<PathBuf>,
    offline_fixtures: Option<PathBuf>,
    persona: Option<PathBuf>,
    instruction_window: Option<InstructionWindow>,
}

fn parse_instruction_window(value: &str) -> Result<InstructionWindow> {
    let (start, count) = value
        .split_once(':')
        .context("Instruction window must be START:COUNT")?;
    anyhow::ensure!(
        !start.is_empty()
            && !count.is_empty()
            && start.bytes().all(|byte| byte.is_ascii_digit())
            && count.bytes().all(|byte| byte.is_ascii_digit()),
        "Instruction window must contain unsigned decimal START:COUNT"
    );
    let window = InstructionWindow {
        start_instruction: start.parse().context("Invalid instruction window start")?,
        max_records: count.parse().context("Invalid instruction window count")?,
    };
    anyhow::ensure!(
        (1..=65_536).contains(&window.max_records),
        "Instruction window count outside bounded profile"
    );
    Ok(window)
}

fn submitted_options(args: impl Iterator<Item = String>) -> Result<SubmittedOptions> {
    let mut args = args;
    let mut service = None;
    let mut max_instructions = None;
    let mut timeout_us = None;
    let mut kernel_code_reference = None;
    let mut offline_fixtures = None;
    let mut persona = None;
    let mut instruction_window = None;
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .with_context(|| format!("{flag} requires a value"))?;
        match flag.as_str() {
            "--service" => {
                anyhow::ensure!(service.is_none(), "--service given twice");
                service = Some(value);
            }
            "--max-instructions" => {
                anyhow::ensure!(max_instructions.is_none(), "--max-instructions given twice");
                max_instructions = Some(value.parse().context("Invalid instruction budget")?);
            }
            "--timeout-us" => {
                anyhow::ensure!(timeout_us.is_none(), "--timeout-us given twice");
                timeout_us = Some(value.parse().context("Invalid wall budget")?);
            }
            "--kernel-code-reference" => {
                anyhow::ensure!(
                    kernel_code_reference.is_none(),
                    "--kernel-code-reference given twice"
                );
                kernel_code_reference = Some(PathBuf::from(value));
            }
            "--offline-fixtures" => {
                anyhow::ensure!(offline_fixtures.is_none(), "--offline-fixtures given twice");
                offline_fixtures = Some(PathBuf::from(value));
            }
            "--persona" => {
                anyhow::ensure!(persona.is_none(), "--persona given twice");
                persona = Some(PathBuf::from(value));
            }
            "--instruction-window" => {
                anyhow::ensure!(
                    instruction_window.is_none(),
                    "--instruction-window given twice"
                );
                instruction_window = Some(parse_instruction_window(&value)?);
            }
            _ => bail!("Unknown submitted-driver option: {flag}"),
        }
    }
    Ok(SubmittedOptions {
        service: service.context("submitted-driver requires --service NAME")?,
        max_instructions: max_instructions.unwrap_or(100_000_000),
        timeout_us: timeout_us.unwrap_or(120_000_000),
        kernel_code_reference,
        offline_fixtures,
        persona,
        instruction_window,
    })
}

#[cfg(test)]
mod submitted_option_tests {
    use super::*;

    fn parse(values: &[&str]) -> Result<SubmittedOptions> {
        submitted_options(values.iter().map(|value| (*value).to_owned()))
    }

    #[test]
    fn submitted_cli_options_bind_once_and_preserve_defaults() {
        assert_eq!(
            parse(&["--service", "TestDrv"]).unwrap(),
            SubmittedOptions {
                service: "TestDrv".into(),
                max_instructions: 100_000_000,
                timeout_us: 120_000_000,
                kernel_code_reference: None,
                offline_fixtures: None,
                persona: None,
                instruction_window: None,
            }
        );
        assert_eq!(
            parse(&[
                "--timeout-us",
                "123",
                "--service",
                "TestDrv",
                "--max-instructions",
                "456",
            ])
            .unwrap(),
            SubmittedOptions {
                service: "TestDrv".into(),
                max_instructions: 456,
                timeout_us: 123,
                kernel_code_reference: None,
                offline_fixtures: None,
                persona: None,
                instruction_window: None,
            }
        );
        for flag in [
            "--service",
            "--max-instructions",
            "--timeout-us",
            "--kernel-code-reference",
            "--offline-fixtures",
            "--persona",
            "--instruction-window",
        ] {
            let (first, second) = if flag == "--instruction-window" {
                ("1:1", "2:2")
            } else {
                ("1", "2")
            };
            let values = ["--service", "TestDrv", flag, first, flag, second];
            assert!(
                parse(&values)
                    .unwrap_err()
                    .to_string()
                    .contains(&format!("{flag} given twice")),
                "{flag}"
            );
        }
        assert!(parse(&["--max-instructions", "5"]).is_err());
        assert_eq!(
            parse(&[
                "--service",
                "TestDrv",
                "--kernel-code-reference",
                "kernel.pe"
            ])
            .unwrap()
            .kernel_code_reference,
            Some(PathBuf::from("kernel.pe"))
        );
        assert!(parse(&["--service", "TestDrv", "--timeout-us"]).is_err());
        assert_eq!(
            parse(&["--service", "TestDrv", "--offline-fixtures", "offline.json"])
                .unwrap()
                .offline_fixtures,
            Some(PathBuf::from("offline.json"))
        );
        assert_eq!(
            parse(&["--service", "TestDrv", "--persona", "persona.json"])
                .unwrap()
                .persona,
            Some(PathBuf::from("persona.json"))
        );
        assert_eq!(
            parse(&["--service", "TestDrv", "--instruction-window", "9:12"])
                .unwrap()
                .instruction_window,
            Some(InstructionWindow {
                start_instruction: 9,
                max_records: 12,
            })
        );
        for value in [
            "",
            "1",
            ":1",
            "1:",
            "1:2:3",
            "-1:2",
            "+1:2",
            "1:0",
            "1:65537",
            "1: 2",
            "18446744073709551616:1",
        ] {
            assert!(
                parse(&["--service", "TestDrv", "--instruction-window", value]).is_err(),
                "{value}"
            );
        }
    }
}
fn main() {
    if let Err(error) = execute() {
        eprintln!("{error:#}");
        std::process::exit(2);
    }
}
fn execute() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None | Some("help" | "--help" | "-h") => println!(
            "Emumee Rust development build\n\npersona (print literal default Windows configuration)\ninspect PATH [--details]\ninspect-analysis-plan PLAN_JSON STAGED_ROOT (read-only; inputs/0000.bin slots)\nverify-analysis-plan PLAN_JSON STAGED_INPUT_ROOT FRESH_OUTPUT_ROOT (contained verify-only; no guest execution)\nverify-analysis-plan-fixture native-a FRESH_OUTPUT_ROOT [--fault swap-slots|tamper-slot|change-request|change-plan|missing-slot]\ninspect-powershell-source PATH (.ps1 bounded read-only; no execution)\ninspect-powershell-report RUN_DIR [SOURCE_PS1] (read-only saved report binding)\ninspect-managed PATH\ninspect-msi-report RUN_DIR [SOURCE_MSI] (read-only saved static report binding)\ninspect-msi PATH\nanalysis-fixture CASE FRESH_OUTPUT_DIR [--arch x86|x64] [--fault NAME]\nmsi-fixture CASE FRESH_OUTPUT_DIR (mini-v3, mini-v4, regular-v3, regular-v4, difat-v3, data-pe, mapped-data-pe, corrupt-fat, truncated, tamper-request, tamper-input, unknown-request-field, foreign-owned-fixture)\ninspect-batch-inputs DIRECTORY [--recursive] [--include-dll] [--include-driver] [--max-samples N] (metadata only; no execution)\ninspect-batch-log PATH (bounded read-only legacy NDJSON structure)\ninspect-batch-sequence LOG_PATH INPUT_ROOT [inventory flags] (read-only declarations)\ninspect-batch-aggregate LOG_PATH INPUT_ROOT REPORT_ROOT [inventory flags] (read-only declaration manifest)\ninspect-batch-report-map LOG_PATH REPORT_ROOT (read-only declared summary binding)\ninspect-report-index ROOT (bounded read-only summary index)\ninspect-report RUN_DIR [--verify-artifacts]\ninspect-driver-capture RUN_DIR (explicit Driver128 consistency only)\ndriver-capture-fixture CASE FRESH_OUTPUT_DIR [--fault NAME] (closed generated recipes only)\nsubmitted-driver SOURCE_SYS FRESH_OUTPUT_DIR --service NAME [--max-instructions N] [--timeout-us N] [--kernel-code-reference PE] [--offline-fixtures JSON] [--persona JSON] [--instruction-window START:COUNT]\ninspect-broker-journal PATH\ninspect-network-fixtures PATH [--normalized]\nrecover-bundle (recover private controller cleanup plan, no analysis)\nbroker-fixture CASE FRESH_OUTPUT_DIR [--arch x86|x64] (normal, miss, dns, crash, partial, hang, bad-id, bad-frame, worker-crash, native-a, native-w, native-miss, native-callback, native-parent, native-partial, native-null, controller-crash, controller-partial, http-binary, http-post, http-headers, http-body-miss, http-chunked-miss, native-binary-a, native-binary-w, native-binary-partial, native-binary-empty, native-binary-miss, winhttp, winhttp-before-receive, winhttp-bad-read, winhttp-bad-available, winhttp-close-parent, winhttp-miss, winhttp-async, winhttp-query-status, winhttp-query-small, winhttp-query-custom, winhttp-query-raw, winhttp-empty, winhttp-upload, winhttp-upload-early, winhttp-upload-bad-count, winhttp-upload-overrun, winhttp-upload-incomplete, winhttp-upload-closed, winhttp-chunked, winhttp-chunked-split, winhttp-chunked-incomplete, winhttp-chunked-malformed, winhttp-chunked-zero)\nmanaged-fixture [--arch x86|x64] [--write-input FRESH_PATH]\nboundary-probe NAME FRESH_OUTPUT_DIR (normal, timeout, output-bytes, output-count, file-stream, directory-stream, fast-output, output-link, abrupt-exit)\nfixture [--arch x86|x64] [--kind KIND] [--iterations N] [--max-instructions N] [--isolated-output DIR]\n\nFixture kinds: kernel-ipi-* (actual perCPU guest rendezvous contexts), kernel-waits-* (real delay and wait-all/any CPU continuations), kernel-thread-objects-* (actual scheduler handles/references and guarded headers), console-* (guest handles/output), kernel-objects-* (owned identities/refs), managed-convert-* (typed Base64), kernel-objects-* (owned System/Driver refs and opaque type identities; handle refs stop), stdio-* (standard FILE/errno/console), crt-format-* (bounded formatting), kernel-environment-* (processor identity and READ/NX public globals), kernel-kernel-environment-* (processor identity and typed READ/NX globals), rundown-* (opaque cache-aware refs; contended teardown/reenable stop), persona-* (environment/identity/directories/command-line), callback-* (bug-check and named bookkeeping, active dispatch stops), mdl-{{lifecycle,alias,read-only-cpu,read-only-api,nx,unmapped,free-active,pool-free-active,flags,geometry,unbuilt}}, registry-{{lifecycle,enumeration,small-buffer,default-value,invalid-handle,closed-handle,read-only,options}}-{{a,w}}, crt-copy, crt-string-overlap, crt-copy-invalid, crt-memory, crt-strings, crt-wide, crt-boundary, crt-read-fault, crt-write-fault, crt-overlap, crt-overflow, crt-rewrite, heap-lifecycle, heap-resize, heap-move, heap-in-place, heap-executable, heap-nx, heap-freed, heap-wrong-owner, heap-double-free, heap-virtual-free, heap-flags, heap-fixed, heap-zero, loop, managed-rva-decode, managed-rva-bytes, managed-rva-i32, managed-rva-zero, managed-rva-twice, managed-rva-bad-handle, managed-rva-missing-field, managed-rva-no-rva, managed-rva-missing-row, managed-rva-no-layout, managed-rva-bad-packing, managed-rva-too-small, managed-rva-bad-rva, managed-rva-reference-field, managed-rva-literal, managed-rva-wrong-array, managed-rva-null-array, managed-rva-bad-signature, managed-rva-handle-branch, managed-file-round-trip, managed-file-overwrite, managed-file-empty, managed-file-empty-exists, managed-file-exists, managed-file-exists-null, managed-file-missing, managed-file-parent-missing, managed-file-null-path, managed-file-null-bytes, managed-file-invalid-path, managed-file-unsupported-path, managed-file-bad-signature, managed-file-bad-assembly, managed-file-bad-array-type, managed-file-escape, managed-file-dedupe, managed-file-partial, managed-array-byte, managed-array-i32, managed-array-string, managed-array-string-zero, managed-array-length, managed-array-length-type, managed-array-native-length, managed-array-local, managed-array-local-null, managed-array-call, managed-array-identity, managed-array-different, managed-array-zero-byte, managed-array-null, managed-array-bounds, managed-array-bad-value, managed-array-bad-opcode, managed-array-too-large, managed-array-negative, managed-array-unknown-type, managed-array-bad-assembly, managed-array-bad-local, managed-array-quota, managed-array-bad-length-type, managed-array-vs-string, managed-framework-console-types, managed-framework-null-or-empty, managed-framework-inequality, managed-framework-strings, managed-framework-concat-identity, managed-framework-string-equality, managed-framework-concat-empty, managed-framework-concat-null, managed-framework-unicode-length, managed-framework-char, managed-framework-null-length, managed-framework-bad-index, managed-framework-bad-assembly, managed-framework-bad-signature, managed-framework-static-virtual, managed-framework-unknown, managed-framework-bad-owner, managed-framework-bad-scope, managed-framework-console, managed-framework-console-null, managed-framework-console-limit, managed-framework-argument-type, managed-string-identity, managed-string-aliases, managed-string-local, managed-string-local-null, managed-string-call, managed-string-return, managed-string-bad-token, managed-string-missing, managed-string-bad-type, managed-string-relational, managed-locals-loop, managed-local-zero, managed-local-indexed, managed-call-arguments, managed-argument-store, managed-void-return, managed-void-call, managed-recursive, managed-deep-recursion, managed-local-uninitialized, managed-local-bad-type, managed-argument-bad-type, managed-return, managed-loop, managed-arithmetic, managed-i64-arithmetic, managed-bad-branch, managed-underflow, managed-divide-zero, managed-unsupported, managed-return-stack, managed-stack-limit, managed-infinite, kernel-catalog-call, kernel-catalog-code-read, kernel-catalog-data-read, pool-lifecycle, pool-executable, pool-nx-execute, pool-freed-read, pool-bad-tag, pool-paged-irql, pool-bad-flags, pool-too-large, pool-double-free, kernel-api-address, user-api-address, user-api, copy, copy-to-code, debug-prompt, prompt-to-code, unsupported-import, api-loop, virtual-memory, virtual-write-protected, virtual-released-read, virtual-reserve-read, virtual-bad-protect-output, virtual-recommit, linked-module, forwarded-module, file-round-trip-a, file-round-trip-w, file-read-only, file-read-code, guarded-mutex, guarded-busy, guarded-bad-release, guarded-irql, critical-underflow, system-thread, system-thread-return, system-thread-bad-start, mutex-handoff, mutex-deadlock, cpu-identity, cpu-time, cpu-bad-xcr, cpu-rewrite, cpu-halt, cpu-tsc-aux, thread-msr, thread-tsc, cpu-tsc-msr-read, cpu-tsc-msr-write, cpu-tsc-msr-wrap, cpu-tsc-adjust, cpu-tsc-adjust-link, cpu-tsc-adjust-reset, cpu-tsc-msr-user, kernel-cpu, kernel-entry, kernel-relocated, kernel-resolve, kernel-resolve-bad-length, kernel-resolve-irql, kernel-resolve-unknown, user-resolve-a, user-resolve-w, user-resolve-unknown, user-resolve-bad-module, kernel-write-protected, kernel-syscall, kernel-syscall-bad-target, kernel-sysret, kernel-sysenter, kernel-sysexit, user-time, kernel-time, time-bad-output, shared-time, shared-time-write, event-auto, event-manual, event-timeout, event-long-timeout, event-absolute, event-deadlock, event-handoff, event-irql, event-alertable, event-tamper\n\nClosed plan controls: plan-fixture CASE ROOT [x86|x64]; inspect-plan-proof ROOT. Fixed fault controls: plan-fault NAME ROOT [x86|x64]; inspect-plan-fault ROOT. Cases: native-a, native-b, native-replay, native-deny, kernel17, kernel19, static-msi.\n\nGeneral sample execution is gated on the remaining Windows model migration."
        ),
        Some("--version" | "-V") => println!(
            "emumee-rs {} ({})",
            env!("CARGO_PKG_VERSION"),
            emumee_engine::backend()
        ),
        Some("persona") => {
            let help = match args.next().as_deref() {
                None => false,
                Some("--help" | "-h") => true,
                _ => bail!("Unexpected persona arguments"),
            };
            anyhow::ensure!(args.next().is_none(), "Unexpected persona arguments");
            if help {
                println!(
                    "Usage: emumee-rs persona\nPrint the literal default Windows configuration."
                );
                return Ok(());
            }
            print!("{}", emumee_core::fullpersona::default_document());
        }
        Some("build-info") => println!(
            "{}",
            serde_json::json!({"source_tree_sha256":env!("EMUMEE_BUILD_SOURCE_SHA256"),"source_files":env!("EMUMEE_BUILD_SOURCE_FILES"),"backend":emumee_engine::backend(),"unicorn_version":"2.1.5"})
        ),
        Some("inspect-network-fixtures") => {
            let path = PathBuf::from(
                args.next()
                    .context("inspect-network-fixtures requires a path")?,
            );
            let normalized = match args.next().as_deref() {
                None => false,
                Some("--normalized") => true,
                _ => bail!("Unknown network fixture inspection option"),
            };
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected network fixture inspection arguments"
            );
            let raw = bounded_input(&path)?;
            let fixtures =
                emumee_core::networkfixtures::Fixtures::parse(&raw).map_err(anyhow::Error::msg)?;
            let result = if normalized {
                fixtures.document()
            } else {
                use sha2::{Digest, Sha256};
                serde_json::json!({"version":1,"rule_count":fixtures.rules().len(),"rules":fixtures.rules().iter().map(|r|serde_json::json!({"id":r.id,"method":r.request.method,"url":r.request.url,"request_bytes":r.request.body.len(),"response_bytes":r.response.body.len(),"request_sha256":format!("{:x}",Sha256::digest(&r.request.body)),"response_sha256":format!("{:x}",Sha256::digest(&r.response.body))})).collect::<Vec<_>>(),"scope":"Read-only offline fixture inspection; no network activity"})
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Some("inspect-analysis-plan") => {
            let plan_path = PathBuf::from(
                args.next()
                    .context("inspect-analysis-plan requires a plan JSON path")?,
            );
            let staged_root = PathBuf::from(args.next().context(
                "inspect-analysis-plan requires a staged root with inputs/0000.bin slots",
            )?);
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected analysis planning arguments"
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&plan_reader::inspect(&plan_path, &staged_root)?)?
            );
        }
        Some("verify-analysis-plan") => {
            let plan = PathBuf::from(
                args.next()
                    .context("verify-analysis-plan requires PLAN_JSON")?,
            );
            let staged_input = PathBuf::from(
                args.next()
                    .context("verify-analysis-plan requires STAGED_INPUT_ROOT")?,
            );
            let output = PathBuf::from(
                args.next()
                    .context("verify-analysis-plan requires FRESH_OUTPUT_ROOT")?,
            );
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected verify-analysis-plan arguments"
            );
            #[cfg(windows)]
            {
                let manifest = general_plan_controller::verify_plan(&plan, &staged_input, &output)?;
                println!("{}", serde_json::to_string_pretty(&manifest)?);
                if manifest["status"] != "verified" {
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (plan, staged_input, output);
                bail!("General admission requires the packaged Windows offline worker");
            }
        }
        Some("verify-analysis-plan-fixture") => {
            let case = args
                .next()
                .context("verify-analysis-plan-fixture requires a case")?;
            anyhow::ensure!(case == "native-a", "Only generated native-a is qualified");
            let output = PathBuf::from(
                args.next()
                    .context("verify-analysis-plan-fixture requires FRESH_OUTPUT_ROOT")?,
            );
            let fault = match args.next().as_deref() {
                None => None,
                Some("--fault") => Some(args.next().context("--fault requires a generated case")?),
                _ => bail!("Unknown generated general admission option"),
            };
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected generated general admission arguments"
            );
            #[cfg(windows)]
            {
                let fault = fault
                    .as_deref()
                    .map(general_plan_controller::GeneratedFault::parse)
                    .transpose()?;
                let manifest = general_plan_controller::verify_fixture(&output, fault)?;
                println!("{}", serde_json::to_string_pretty(&manifest)?);
                let expected = if fault.is_some() {
                    "verified_refusal"
                } else {
                    "verified"
                };
                if manifest["status"] != expected {
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (output, fault);
                bail!("Generated general admission requires the packaged Windows offline worker");
            }
        }
        Some("verify-general-private-boundary-fixture") => {
            let case = args
                .next()
                .context("General private boundary requires replay or deny")?;
            anyhow::ensure!(
                matches!(case.as_str(), "replay" | "deny"),
                "Unknown general private boundary fixture"
            );
            let output = PathBuf::from(
                args.next()
                    .context("General private boundary requires a fresh output root")?,
            );
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected general private boundary arguments"
            );
            #[cfg(windows)]
            {
                let manifest =
                    general_boundary_controller::verify_fixture(&output, case == "replay")?;
                println!("{}", serde_json::to_string_pretty(&manifest)?);
                if manifest["status"] != "verified" {
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (case, output);
                bail!("General private boundary requires packaged Windows offline roles");
            }
        }
        Some("verify-general-driver128-boundary-fixture") => {
            let output = PathBuf::from(
                args.next()
                    .context("Driver128 boundary fixture requires a fresh output root")?,
            );
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected Driver128 boundary fixture arguments"
            );
            #[cfg(windows)]
            {
                let manifest = general_boundary_controller::verify_driver128_fixture(&output)?;
                println!("{}", serde_json::to_string_pretty(&manifest)?);
                if manifest["status"] != "verified" {
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = output;
                bail!("Driver128 boundary fixture requires packaged Windows offline roles");
            }
        }
        Some("verify-general-rpc-fixture") => {
            let output = PathBuf::from(
                args.next()
                    .context("General RPC fixture requires a fresh output root")?,
            );
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected general RPC fixture arguments"
            );
            #[cfg(windows)]
            {
                let manifest = general_rpc_controller::verify_fixture(&output)?;
                println!("{}", serde_json::to_string_pretty(&manifest)?);
                if manifest["status"] != "verified" {
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = output;
                bail!("General RPC fixture requires packaged Windows offline roles");
            }
        }
        Some("verify-general-rpc-cleanup-fixture") => {
            let output = PathBuf::from(
                args.next()
                    .context("General RPC cleanup fixture requires a fresh output root")?,
            );
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected general RPC cleanup fixture arguments"
            );
            #[cfg(windows)]
            {
                // The fixed fault intentionally returns an error after both
                // generated children exit and before tracked cleanup.
                let _ = general_rpc_controller::verify_cleanup_fault(&output)?;
                anyhow::bail!("General RPC cleanup fault unexpectedly completed");
            }
            #[cfg(not(windows))]
            {
                let _ = output;
                bail!("General RPC cleanup fixture requires packaged Windows offline roles");
            }
        }
        Some("submitted-driver") => {
            let source = PathBuf::from(
                args.next()
                    .context("submitted-driver requires a .sys input")?,
            );
            let root = PathBuf::from(
                args.next()
                    .context("submitted-driver requires a fresh output root")?,
            );
            let options = submitted_options(args)?;
            #[cfg(windows)]
            {
                let result = driver_input_controller::run(
                    &source,
                    &root,
                    &options.service,
                    options.max_instructions,
                    options.timeout_us,
                    driver_input_controller::OptionalPaths {
                        kernel_code_reference: options.kernel_code_reference.as_deref(),
                        offline_fixtures: options.offline_fixtures.as_deref(),
                        persona: options.persona.as_deref(),
                        instruction_window: options.instruction_window,
                    },
                )?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                if result["status"] != "verified" || result["guest_status"] != "processed" {
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (source, root, options);
                bail!("Submitted drivers require the packaged Windows offline worker");
            }
        }
        Some("driver-capture-fixture") => {
            let case = args
                .next()
                .context("driver-capture-fixture requires a closed recipe")?;
            let root = PathBuf::from(
                args.next()
                    .context("driver-capture-fixture requires a fresh output root")?,
            );
            let fault = match args.next().as_deref() {
                None => String::from("none"),
                Some("--fault") => args.next().context("--fault requires a name")?,
                _ => bail!("Unexpected Driver128 option"),
            };
            anyhow::ensure!(args.next().is_none(), "Unexpected Driver128 arguments");
            #[cfg(windows)]
            {
                let result = driver_capture_controller::run(&root, &case, &fault)?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                if result["status"] != "completed" {
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (case, root, fault);
                bail!("Driver128 controls require a packaged Windows worker");
            }
        }
        Some("inspect-driver-capture") => {
            let root = PathBuf::from(
                args.next()
                    .context("inspect-driver-capture requires a run root")?,
            );
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected Driver128 inspection arguments"
            );
            #[cfg(windows)]
            println!(
                "{}",
                serde_json::to_string_pretty(&driver_capture_reader::inspect(&root)?)?
            );
            #[cfg(not(windows))]
            {
                let _ = root;
                bail!("Pinned Driver128 inspection requires Windows");
            }
        }
        Some("analysis-fixture") => {
            let case = args
                .next()
                .context("analysis-fixture requires a closed generated case")?;
            let root = PathBuf::from(
                args.next()
                    .context("analysis-fixture requires a fresh output root")?,
            );
            let mut architecture = Architecture::X64;
            let mut fault = String::from("none");
            while let Some(option) = args.next() {
                match option.as_str() {
                    "--arch" => {
                        architecture = match args.next().as_deref() {
                            Some("x86") => Architecture::X86,
                            Some("x64") => Architecture::X64,
                            _ => bail!("Expected x86 or x64"),
                        }
                    }
                    "--fault" => {
                        fault = args
                            .next()
                            .context("--fault requires a closed control name")?
                    }
                    _ => bail!("Unknown generated analysis option"),
                }
            }
            #[cfg(windows)]
            {
                let result = analysis_fixture::run(&root, &case, architecture, &fault)?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                if result["status"] != "completed" {
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (case, root, architecture, fault);
                bail!("Generated analysis requires the packaged Windows worker");
            }
        }

        Some("msi-fixture") => {
            let case = args
                .next()
                .context("msi-fixture requires a closed generated case")?;
            let root = PathBuf::from(
                args.next()
                    .context("msi-fixture requires a fresh output directory")?,
            );
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected static MSI fixture arguments"
            );
            #[cfg(windows)]
            {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&msi_fixture::run(&root, &case)?)?
                );
            }
            #[cfg(not(windows))]
            {
                let _ = (case, root);
                bail!("Static MSI fixtures require Windows");
            }
        }
        Some("inspect-msi-report") => {
            let run = PathBuf::from(
                args.next()
                    .context("inspect-msi-report needs a run directory")?,
            );
            let source = args.next().map(PathBuf::from);
            anyhow::ensure!(args.next().is_none(), "Unexpected MSI report arguments");
            println!(
                "{}",
                serde_json::to_string_pretty(&msi_report::inspect(&run, source.as_deref())?)?
            );
        }
        Some("inspect-msi") => {
            let path = PathBuf::from(args.next().context("inspect-msi requires an input path")?);
            anyhow::ensure!(args.next().is_none(), "Unexpected MSI inspection arguments");
            println!(
                "{}",
                serde_json::to_string_pretty(&msi_reader::inspect(&path)?)?
            );
        }
        Some("inspect-batch-inputs") => {
            let (root, options) = batch_inventory::parse(args)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&batch_inventory::inspect(&root, &options)?)?
            );
        }
        Some("inspect-batch-log") => {
            let path = PathBuf::from(
                args.next()
                    .context("inspect-batch-log requires a log path")?,
            );
            anyhow::ensure!(args.next().is_none(), "Unexpected batch log arguments");
            println!(
                "{}",
                serde_json::to_string_pretty(&batch_log::inspect(&path)?)?
            );
        }
        Some("inspect-batch-sequence") => {
            let log = PathBuf::from(
                args.next()
                    .context("inspect-batch-sequence needs a log path")?,
            );
            let (root, options) = batch_inventory::parse(args)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&batch_sequence::inspect(&log, &root, &options)?)?
            );
        }
        Some("inspect-batch-aggregate") => {
            let log = PathBuf::from(
                args.next()
                    .context("inspect-batch-aggregate needs a log path")?,
            );
            let input = args
                .next()
                .context("inspect-batch-aggregate needs an input root")?;
            let reports = PathBuf::from(
                args.next()
                    .context("inspect-batch-aggregate needs a report root")?,
            );
            let (input, options) = batch_inventory::parse(std::iter::once(input).chain(args))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&batch_aggregate::inspect(
                    &log, &input, &reports, &options
                )?)?
            );
        }
        Some("inspect-batch-report-map") => {
            let log = PathBuf::from(
                args.next()
                    .context("inspect-batch-report-map needs a log path")?,
            );
            let root = PathBuf::from(
                args.next()
                    .context("inspect-batch-report-map needs a report root")?,
            );
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected batch report map arguments"
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&batch_report_map::inspect(&log, &root)?)?
            );
        }
        Some("inspect-report-index") => {
            let root = PathBuf::from(
                args.next()
                    .context("inspect-report-index requires a report root")?,
            );
            anyhow::ensure!(args.next().is_none(), "Unexpected report index arguments");
            println!(
                "{}",
                serde_json::to_string_pretty(&report_index::inspect(&root)?)?
            );
        }
        Some("inspect-report") => {
            let root = PathBuf::from(
                args.next()
                    .context("inspect-report requires a run directory")?,
            );
            let verify_artifacts = match args.next().as_deref() {
                None => false,
                Some("--verify-artifacts") => true,
                _ => bail!("Unexpected report inspection arguments"),
            };
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected report inspection arguments"
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&report_reader::inspect(&root, verify_artifacts)?)?
            );
        }
        Some("recover-bundle") => {
            anyhow::ensure!(args.next().is_none(), "Unexpected recovery arguments");
            #[cfg(windows)]
            {
                let verified = worker::verified_bundle()?;
                println!("{}", serde_json::to_string_pretty(&verified.recovery)?);
            }
            #[cfg(not(windows))]
            bail!("Controller recovery requires Windows");
        }
        Some("broker-fixture") => {
            let probe = emumee_core::broker::Probe::parse(
                &args
                    .next()
                    .context("broker-fixture requires a fixed case")?,
            )
            .context("Unknown broker fixture case")?;
            let root = PathBuf::from(
                args.next()
                    .context("broker-fixture requires a fresh output root")?,
            );
            let architecture = match args.next().as_deref() {
                None => Architecture::X64,
                Some("--arch") => match args.next().as_deref() {
                    Some("x64") => Architecture::X64,
                    Some("x86") => Architecture::X86,
                    _ => bail!("Broker architecture must be x86 or x64"),
                },
                _ => bail!("Unexpected broker fixture arguments"),
            };
            anyhow::ensure!(args.next().is_none(), "Unexpected broker fixture arguments");
            #[cfg(windows)]
            {
                let result = broker::fixture(&root, probe, architecture)?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                if result["qualified"] != true {
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (probe, root, architecture);
                bail!("Broker fixture requires Windows");
            }
        }
        Some("boundary-probe") => {
            let name = args
                .next()
                .context("boundary-probe requires a fixed probe name")?;
            let probe = BoundaryProbe::parse(&name).context("Unknown boundary probe")?;
            let root = PathBuf::from(
                args.next()
                    .context("boundary-probe requires a fresh output directory")?,
            );
            anyhow::ensure!(args.next().is_none(), "Unexpected boundary probe arguments");
            #[cfg(windows)]
            println!(
                "{}",
                serde_json::to_string_pretty(&worker::isolated_probe(&root, probe)?)?
            );
            #[cfg(not(windows))]
            {
                let _ = (root, probe);
                bail!("Boundary probes require Windows");
            }
        }
        Some("inspect-broker-journal") => {
            let path = PathBuf::from(
                args.next()
                    .context("inspect-broker-journal requires a snapshot file")?,
            );
            anyhow::ensure!(args.next().is_none(), "Unexpected journal arguments");
            #[cfg(windows)]
            let data = emumee_platform::windows::read_regular(
                &path,
                emumee_core::broker_journal::MAX_JOURNAL_BYTES,
                None,
            )?;
            #[cfg(not(windows))]
            let data = {
                let data = bounded_input(&path)?;
                anyhow::ensure!(
                    data.len() <= emumee_core::broker_journal::MAX_JOURNAL_BYTES,
                    "Journal exceeds bound"
                );
                data
            };
            let recovered = emumee_core::broker_journal::recover(&data)?;
            println!("{}", serde_json::to_string_pretty(&recovered)?);
            if !recovered.closed {
                std::process::exit(1);
            }
        }
        Some("inspect-powershell-source") => {
            let path = PathBuf::from(
                args.next()
                    .context("inspect-powershell-source requires a .ps1 input")?,
            );
            if args.next().is_some() {
                bail!("Unexpected PowerShell source inspection arguments");
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&powershell_source::inspect(&path)?)?
            );
        }
        Some("inspect-powershell-report") => {
            let run = PathBuf::from(
                args.next()
                    .context("inspect-powershell-report needs a run directory")?,
            );
            let source = args.next().map(PathBuf::from);
            anyhow::ensure!(
                args.next().is_none(),
                "Unexpected PowerShell report arguments"
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&powershell_report::inspect(
                    &run,
                    source.as_deref()
                )?)?
            );
        }
        Some("inspect-managed") => {
            let path = PathBuf::from(args.next().context("inspect-managed requires a file")?);
            if args.next().is_some() {
                bail!("Unexpected inspect-managed arguments");
            }
            let bytes = bounded_input(&path)?;
            let metadata = emumee_core::managed::Metadata::parse(
                &bytes,
                &path.file_name().unwrap_or_default().to_string_lossy(),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"sample":&metadata.pe.sample,"managed":metadata.describe()?})
                )?
            );
        }
        Some("managed-fixture") => {
            let mut architecture = Architecture::X64;
            let mut destination = None;
            while let Some(flag) = args.next() {
                let value = args
                    .next()
                    .with_context(|| format!("{flag} requires a value"))?;
                match flag.as_str() {
                    "--arch" => {
                        architecture = match value.as_str() {
                            "x86" => Architecture::X86,
                            "x64" => Architecture::X64,
                            _ => bail!("Architecture must be x86 or x64"),
                        }
                    }
                    "--write-input" => destination = Some(PathBuf::from(value)),
                    _ => bail!("Unknown managed fixture option: {flag}"),
                }
            }
            let bytes = emumee_core::fixtures::managed_probe(architecture);
            let metadata = emumee_core::managed::Metadata::parse(&bytes, "managed-fixture.exe")?;
            if let Some(path) = destination {
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .with_context(|| format!("Cannot create fresh fixture {}", path.display()))?;
                file.write_all(&bytes)?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"sample":&metadata.pe.sample,"managed":metadata.describe()?})
                )?
            );
        }
        Some("inspect") => {
            let path = PathBuf::from(args.next().context("inspect requires a file")?);
            let details = match args.next().as_deref() {
                None => false,
                Some("--details") => true,
                _ => bail!("Expected --details"),
            };
            if args.next().is_some() {
                bail!("Unexpected inspect arguments");
            }
            let bytes = bounded_input(&path)?;
            let pe = PeImage::parse(
                &bytes,
                &path.file_name().unwrap_or_default().to_string_lossy(),
            )?;
            println!(
                "{}",
                if details {
                    serde_json::to_string_pretty(&pe)?
                } else {
                    serde_json::to_string_pretty(&pe.sample)?
                }
            );
        }
        Some("fixture") => {
            let mut architecture = Architecture::X64;
            let mut iterations = 1_000_000u32;
            let mut budget = 30_000_000u64;
            let mut isolated_output = None;
            let mut kind = FixtureKind::Loop;
            while let Some(flag) = args.next() {
                let value = args
                    .next()
                    .with_context(|| format!("{flag} requires a value"))?;
                match flag.as_str() {
                    "--arch" => {
                        architecture = match value.as_str() {
                            "x86" => Architecture::X86,
                            "x64" => Architecture::X64,
                            _ => bail!("Architecture must be x86 or x64"),
                        }
                    }
                    "--iterations" => iterations = value.parse().context("Invalid iterations")?,
                    "--max-instructions" => {
                        budget = value.parse().context("Invalid instruction budget")?
                    }
                    "--isolated-output" => isolated_output = Some(PathBuf::from(value)),
                    "--kind" => {
                        kind =
                            FixtureKind::parse(&value).context("Unknown generated fixture kind")?
                    }
                    _ => bail!("Unknown fixture option: {flag}"),
                }
            }
            if let Some(root) = isolated_output {
                #[cfg(windows)]
                {
                    let result =
                        worker::isolated_fixture(&root, architecture, iterations, budget, kind)?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    if result["result"]["execution"]["completion_reason"] != "entry_return" {
                        std::process::exit(1);
                    }
                    return Ok(());
                }
                #[cfg(not(windows))]
                {
                    let _ = root;
                    bail!("Isolated fixtures require Windows");
                }
            }
            let result = emumee_engine::run_fixture_kind(architecture, kind, iterations, budget)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if result.completion_reason() != "entry_return" {
                std::process::exit(1);
            }
        }
        Some("inspect-plan-proof") => {
            let root = PathBuf::from(
                args.next()
                    .context("inspect-plan-proof requires a run root")?,
            );
            anyhow::ensure!(args.next().is_none(), "Unexpected proof inspection options");
            #[cfg(windows)]
            {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&plan_controller::inspect(&root)?)?
                );
            }
            #[cfg(not(windows))]
            {
                let _ = root;
                bail!("Proof inspection requires Windows safe readers");
            }
        }
        Some("plan-fault") => {
            let name = args
                .next()
                .context("plan-fault requires a fixed scenario")?;
            let fault = emumee_core::plan_runtime::Fault::parse(&name)
                .context("Unknown fixed plan fault")?;
            let root = PathBuf::from(args.next().context("plan-fault requires a fresh root")?);
            let arch = match args.next().as_deref() {
                None | Some("x64") => Architecture::X64,
                Some("x86") => Architecture::X86,
                _ => bail!("Expected x86 or x64"),
            };
            anyhow::ensure!(args.next().is_none(), "Unexpected closed fault options");
            #[cfg(windows)]
            {
                let v = plan_controller::run_fault(&root, fault, arch)?;
                println!("{}", serde_json::to_string_pretty(&v)?);
                if v["verified"] != true {
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (root, fault, arch);
                bail!("Closed fault role requires Windows");
            }
        }
        Some("inspect-plan-fault") => {
            let root = PathBuf::from(args.next().context("inspect-plan-fault requires a root")?);
            anyhow::ensure!(args.next().is_none(), "Unexpected fault inspection options");
            #[cfg(windows)]
            println!(
                "{}",
                serde_json::to_string_pretty(&plan_controller::inspect_fault(&root)?)?
            );
            #[cfg(not(windows))]
            {
                let _ = root;
                bail!("Fault inspection requires Windows");
            }
        }
        Some("plan-fixture") => {
            let name = args.next().context("plan-fixture requires a closed case")?;
            let case = emumee_core::plan_runtime::Case::parse(&name)
                .context("Unknown closed plan case")?;
            let root = PathBuf::from(
                args.next()
                    .context("plan-fixture requires a fresh output root")?,
            );
            let arch = match args.next().as_deref() {
                None | Some("x64") => Architecture::X64,
                Some("x86") => Architecture::X86,
                _ => bail!("Expected x86 or x64"),
            };
            anyhow::ensure!(args.next().is_none(), "Unexpected closed plan options");
            #[cfg(windows)]
            {
                let value = plan_controller::run(&root, case, arch)?;
                println!("{}", serde_json::to_string_pretty(&value)?);
                if value["verified"] != true {
                    std::process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (root, case, arch);
                bail!("Closed plan worker requires Windows");
            }
        }
        Some("run") => bail!(
            "General sample execution is disabled until the Rust AppContainer and Windows API ports are qualified; this build never falls back to Python"
        ),
        Some(other) => bail!("Unknown command: {other}"),
    }
    Ok(())
}

#[cfg(windows)]
mod plan_controller;
