//! Offline submitted user PE role. Containment precedes every input read.
use super::{save_artifacts, save_new};
use anyhow::{Result, ensure};
use emumee_core::{
    report_bundle::{bounded_json, digest},
    user_input::{MAX_REQUEST, MAX_RESULT, Request},
};
use emumee_platform::windows::{prepare_worker, read_regular};
use serde_json::json;
use std::path::Path;

pub fn execute(root: &Path, expected: &str) -> Result<()> {
    let containment = prepare_worker()?;
    let output = root.join("worker");
    save_new(
        &output.join("containment.json"),
        &serde_json::to_vec(&containment)?,
    )?;
    let result = (|| -> Result<()> {
        let raw = read_regular(&root.join("request.json"), MAX_REQUEST, Some(root))?;
        ensure!(digest(&raw) == expected, "Submitted user request changed");
        let request = Request::parse(&raw).map_err(anyhow::Error::msg)?;
        let bytes = read_regular(
            &root.join("input.pe"),
            emumee_core::pe::MAX_INPUT,
            Some(root),
        )?;
        request.verify_input(&bytes).map_err(anyhow::Error::msg)?;
        let persona = if let Some(hash) = &request.persona_sha256 {
            let raw = read_regular(
                &root.join("persona.json"),
                emumee_core::driver_input::MAX_PERSONA,
                Some(root),
            )?;
            ensure!(digest(&raw) == *hash, "Submitted user persona changed");
            Some(raw)
        } else {
            ensure!(
                !root.join("persona.json").exists(),
                "Unexpected submitted persona"
            );
            None
        };
        let execution = emumee_engine::user::run(&request, &bytes, persona.as_deref())?;
        save_artifacts(&output, &execution.artifacts)?;
        let result = json!({"schema":1,"profile":request.profile,"run_id":request.run_id,
            "request_sha256":expected,"input_sha256":request.input_sha256,
            "containment":containment,"execution":execution});
        save_new(
            &output.join("result.json"),
            &bounded_json(&result, MAX_RESULT)?,
        )?;
        Ok(())
    })();
    if let Err(error) = &result {
        save_new(
            &output.join("error.txt"),
            format!("{error:#}")
                .chars()
                .take(8192)
                .collect::<String>()
                .as_bytes(),
        )?;
    }
    result
}
