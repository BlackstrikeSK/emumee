//! Dedicated contained worker role for a submitted static Linux guest.
use anyhow::{Context, Result, ensure};
use emumee_core::linux_request::{LinuxRequest, MAX_INPUT, MAX_LIBRARY_INPUT};
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
        let mut staged = Vec::with_capacity(request.libraries.len());
        for (index, library) in request.libraries.iter().enumerate() {
            let path = root.join(format!("lib-{index:04}.elf"));
            #[cfg(windows)]
            let bytes = read_regular(&path, MAX_LIBRARY_INPUT, Some(&root))?;
            #[cfg(target_os = "linux")]
            let bytes = read_linux_regular(&path, MAX_LIBRARY_INPUT)?;
            ensure!(
                bytes.len() as u64 == library.size
                    && format!("{:x}", Sha256::digest(&bytes)) == library.sha256,
                "Staged library differs from request"
            );
            staged.push((library.name.clone(), bytes));
        }
        let references: Vec<(&str, &[u8])> = staged.iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice())).collect();
        let execution = match request.profile.as_str() {
            "static_x64_v1" => emumee_engine::linux::run_static(
                &input,
                request.max_instructions,
                request.timeout_us,
            )?,
            "pie_x64_v1" => emumee_engine::linux::run_pie(
                &input,
                request.max_instructions,
                request.timeout_us,
            )?,
            "static_x86_v1" => emumee_engine::linux::run_static32(
                &input,
                request.max_instructions,
                request.timeout_us,
            )?,
            "pie_x86_v1" => emumee_engine::linux::run_pie32(
                &input,
                request.max_instructions,
                request.timeout_us,
            )?,
            "shared_x64_v1" => emumee_engine::linux::run_shared(
                &input,
                &references,
                request.max_instructions,
                request.timeout_us,
            )?,
            _ => anyhow::bail!("Unsupported Linux guest profile"),
        };
        let report = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": request.schema,
            "request_sha256": expected,
            "input_sha256": request.input_sha256,
            "profile": request.profile,
            "libraries": request.libraries,
            "containment": containment,
            "execution": execution,
            "scope": if cfg!(windows) {
                "Linux guest under the packaged Windows offline worker"
            } else {
                "Linux guest under the native Linux confined worker"
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
