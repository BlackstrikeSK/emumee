//! Driver128 reader; explicit opt-in, no default legacy reader expansion.
use anyhow::{Result, ensure};
use emumee_core::{
    driver_capture_reports::{self as reports, Binding, Summary, VerifiedProjection},
    reports as legacy,
};
use emumee_platform::windows::{read_regular, with_driver_regular};
use std::path::Path;
pub(crate) fn verify(
    root: &Path,
    summary_name: &str,
    expected: Option<&Binding>,
) -> Result<(Summary, Vec<u8>)> {
    ensure!(
        matches!(summary_name, "summary.json" | "worker-summary.json"),
        "Invalid fixed Driver128 summary name"
    );
    let raw = read_regular(
        &root.join(summary_name),
        legacy::MAX_SUMMARY_BYTES,
        Some(root),
    )?;
    let parsed = Summary::parse(&raw)?;
    let expected = expected.unwrap_or(&parsed.binding);
    let engine = read_regular(
        &root.join("engine-report.json"),
        legacy::MAX_ENGINE_BYTES,
        Some(root),
    )?;
    let network = read_regular(
        &root.join("network-broker.json"),
        legacy::MAX_NETWORK_REPORT_BYTES,
        Some(root),
    )?;
    let manifest = read_regular(
        &root.join("artifacts/manifest.json"),
        1024 * 1024,
        Some(root),
    )?;
    let checkpoint = read_regular(
        &root.join("artifact-checkpoint.json"),
        1024 * 1024,
        Some(root),
    )?;
    let verified = reports::verify(
        &raw,
        &engine,
        &network,
        &manifest,
        &checkpoint,
        expected,
        |record| {
            with_driver_regular(
                &root.join("artifacts").join(&record.filename),
                record.size,
                root,
                |read| {
                    Ok(VerifiedProjection::for_record(record, |offset, count| {
                        read(offset, count).ok()
                    })?)
                },
            )
            .map_err(|_| reports::Error("safe pinned Driver128 payload verification"))
        },
    )?;
    Ok((verified, engine))
}
pub fn inspect(root: &Path) -> Result<serde_json::Value> {
    let root = std::path::absolute(root)?;
    let (verified, _) = verify(&root, "summary.json", None)?;
    Ok(
        serde_json::json!({"schema":1,"profile":"driver128_v1","id":verified.summary.id,"status":verified.summary.status,"integrity":"verified_documents_payloads_chunks_reconstruction","artifacts":verified.artifacts.len(),
        "bytes":verified.artifacts.iter().map(|r|r.size).sum::<u64>(),"execution_authority":"declared_evidence_only","scope":"Read-only explicit Driver128 report consistency; not source authenticity, arbitrary execution or confirmed unpacking"}),
    )
}
