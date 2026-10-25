//! Dedicated contained worker role for a submitted static Linux guest.
use anyhow::{Context, Result, ensure};
use emumee_core::linux_request::{LinuxRequest, MAX_INPUT};
use emumee_platform::windows::{prepare_worker, read_regular};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::save_new;

pub fn execute(root: &Path, expected: &str) -> Result<()> {
    let containment = prepare_worker()?;
    let root = std::path::absolute(root)?;
    let result = (|| -> Result<()> {
        let raw = read_regular(&root.join("linux-request.json"), 4096, Some(&root))?;
        ensure!(
            format!("{:x}", Sha256::digest(&raw)) == expected,
            "Linux worker request hash changed"
        );
        let request: LinuxRequest = serde_json::from_slice(&raw)?;
        request.validate().map_err(anyhow::Error::msg)?;
        let input = read_regular(&root.join("input.elf"), MAX_INPUT, Some(&root))?;
        ensure!(
            input.len() as u64 == request.input_size
                && format!("{:x}", Sha256::digest(&input)) == request.input_sha256,
            "Linux worker input differs from request"
        );
        let execution =
            emumee_engine::linux::run_static(&input, request.max_instructions, request.timeout_us)?;
        let report = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": 1,
            "request_sha256": expected,
            "input_sha256": request.input_sha256,
            "containment": containment,
            "execution": execution,
            "scope": "Static x86-64 Linux guest under the packaged Windows offline worker"
        }))?;
        ensure!(
            report.len() <= 4 * 1024 * 1024,
            "Linux report exceeds 4 MiB"
        );
        save_new(&root.join("linux-result.json"), &report)?;
        Ok(())
    })();
    if let Err(error) = &result {
        let message = format!("{error:#}").chars().take(8192).collect::<String>();
        let _ = save_new(&root.join("linux-error.txt"), message.as_bytes());
    }
    result.context("Contained Linux guest role failed")
}
