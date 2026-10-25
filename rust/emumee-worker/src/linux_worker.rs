//! Dedicated contained worker role for a submitted static Linux guest.
use anyhow::{Context, Result, ensure};
use emumee_core::linux_request::{LinuxRequest, MAX_INPUT};
#[cfg(target_os = "linux")]
use emumee_platform::linux::{
    prepare_worker as prepare_linux_worker, read_regular as read_linux_regular,
};
#[cfg(windows)]
use emumee_platform::windows::{prepare_worker, read_regular};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::save_new;

pub fn execute(root: &Path, expected: &str) -> Result<()> {
    #[cfg(windows)]
    let containment = prepare_worker()?;
    #[cfg(target_os = "linux")]
    let containment = prepare_linux_worker(root)?;
    #[cfg(windows)]
    let root = std::path::absolute(root)?;
    #[cfg(target_os = "linux")]
    let root = Path::new("/").to_path_buf();
    let result = (|| -> Result<()> {
        #[cfg(windows)]
        let raw = read_regular(&root.join("linux-request.json"), 4096, Some(&root))?;
        #[cfg(target_os = "linux")]
        let raw = read_linux_regular(&root.join("linux-request.json"), 4096)?;
        ensure!(
            format!("{:x}", Sha256::digest(&raw)) == expected,
            "Linux worker request hash changed"
        );
        let request: LinuxRequest = serde_json::from_slice(&raw)?;
        request.validate().map_err(anyhow::Error::msg)?;
        #[cfg(windows)]
        let input = read_regular(&root.join("input.elf"), MAX_INPUT, Some(&root))?;
        #[cfg(target_os = "linux")]
        let input = read_linux_regular(&root.join("input.elf"), MAX_INPUT)?;
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
            "scope": if cfg!(windows) {
                "Static x86-64 Linux guest under the packaged Windows offline worker"
            } else {
                "Static x86-64 Linux guest under the native Linux confined worker"
            }
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
