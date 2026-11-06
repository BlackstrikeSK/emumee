use super::*;
use emumee_core::{
    fixtures::{self, LoaderFixture},
    pe::Architecture,
    user_input::{InputKind, StagedFile},
};

pub fn run(case: &str, root: &Path, architecture: Architecture) -> Result<Value> {
    let reason = match case {
        "normal" | "parent-options" | "parent-artifact" => None,
        "request" => Some("request changed"),
        "primary" => Some("input hash/size changed"),
        "slot" | "swap" | "hash" => Some("hash/size changed"),
        "missing" | "extra" => Some("slot inventory differs"),
        "persona" => Some("persona changed"),
        "persona-missing" => Some("os error 2"),
        "persona-unexpected" => Some("Unexpected submitted persona"),
        "schema" => Some("identity/profile"),
        "options" => Some("argument quoting"),
        "size" => Some("file type, links or size"),
        "path" => Some("Invalid or duplicate submitted guest file"),
        "quota" => Some("staged byte/module quota"),
        "architecture" => Some("same-architecture native DLL"),
        "partial-load" => Some("overlapping"),
        _ => anyhow::bail!("Unknown submitted binding fixture"),
    };
    let verified = verified_bundle()?;
    let root = std::path::absolute(root)?;
    verify_output_location(&verified.path, &root)?;
    let (bytes, companions) = fixtures::native_loader_probe(architecture, LoaderFixture::Basic);
    let mut payloads = companions
        .iter()
        .map(|(_, bytes)| bytes.clone())
        .collect::<Vec<_>>();
    let mut staged = companions
        .iter()
        .map(|(name, bytes)| StagedFile {
            kind: InputKind::Companion,
            guest_path: format!(r"C:\lib\{name}"),
            size: bytes.len() as u64,
            sha256: digest(bytes),
        })
        .collect::<Vec<_>>();
    payloads.push(b"DATA".to_vec());
    staged.push(StagedFile {
        kind: InputKind::File,
        guest_path: r"C:\data\input.bin".into(),
        size: 4,
        sha256: digest(b"DATA"),
    });
    let persona = emumee_core::fullpersona::default_document().as_bytes();
    let mut request = Request {
        schema: 2,
        profile: PROFILE.into(),
        run_id: run_id()?,
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "sample.exe".into(),
        arguments: vec!["two words".into()],
        max_instructions: 4000,
        timeout_us: 1_000_000,
        persona_sha256: Some(digest(persona)),
        clock_utc_filetime: 134377488000000000,
        staged,
        invocation: emumee_core::user_input::Invocation {
            environment: vec![("TOKEN".into(), Some("bound".into()))],
            force_quotes: vec![0],
            all_exports: false,
        },
    };
    let original = bounded_json(&request, MAX_REQUEST)?;
    let original_hash = digest(&original);
    match case {
        "schema" => request.schema = 99,
        "options" => request.invocation.force_quotes = vec![9],
        "size" => request.staged[0].size = 1,
        "hash" => request.staged[0].sha256 = "a".repeat(64),
        "path" => request.staged[0].guest_path = r"C:\..\escape".into(),
        "quota" => {
            request.staged = (0..5)
                .map(|index| StagedFile {
                    kind: InputKind::File,
                    guest_path: format!(r"C:\quota{index}"),
                    size: 32 * 1024 * 1024,
                    sha256: digest(b"DATA"),
                })
                .collect();
        }
        "persona-unexpected" => request.persona_sha256 = None,
        "architecture" => {
            let (_, foreign) = fixtures::native_loader_probe(
                if architecture == Architecture::X86 {
                    Architecture::X64
                } else {
                    Architecture::X86
                },
                LoaderFixture::Basic,
            );
            payloads[0] = foreign[0].1.clone();
            request.staged[0].size = payloads[0].len() as u64;
            request.staged[0].sha256 = digest(&payloads[0]);
        }
        "partial-load" => {
            let primary = emumee_core::pe::PeImage::parse(&bytes, "sample.exe")?;
            let offset = 0x98
                + if architecture == Architecture::X64 {
                    24
                } else {
                    28
                };
            payloads[0][offset..offset + architecture.width()]
                .copy_from_slice(&primary.image_base.to_le_bytes()[..architecture.width()]);
            request.staged[0].sha256 = digest(&payloads[0]);
        }
        "request" => request.invocation.all_exports = true,
        _ => {}
    }
    let raw = bounded_json(&request, MAX_REQUEST)?;
    let expected = if case == "request" {
        original_hash
    } else {
        digest(&raw)
    };
    staging::publish(&root, &bytes, &raw, Some(persona), &payloads)?;
    match case {
        "primary" => std::fs::write(root.join("input.pe"), b"changed")?,
        "slot" => std::fs::write(root.join("inputs/0000.bin"), b"changed")?,
        "swap" => {
            std::fs::write(root.join("inputs/0000.bin"), payloads.last().unwrap())?;
        }
        "missing" => std::fs::remove_file(root.join("inputs/0000.bin"))?,
        "extra" => save_new(&root.join("inputs/9999.bin"), b"extra")?,
        "persona" => std::fs::write(root.join("persona.json"), b"changed")?,
        "persona-missing" => std::fs::remove_file(root.join("persona.json"))?,
        _ => {}
    }
    let stopped = launch_user(
        &verified,
        &root,
        &[
            OsString::from("--submitted-user"),
            root.as_os_str().to_owned(),
            OsString::from(&expected),
        ],
        OutputLimits {
            max_bytes: 512 * 1024 * 1024,
            max_entries: 4200,
            max_directories: 8,
            max_depth: 4,
        },
        31_000,
    )?;
    ensure!(
        stopped.reason == WorkerStop::Exited,
        "Binding fixture worker stop differs"
    );
    if let Some(reason) = reason {
        ensure!(
            stopped.exit_code == 2 && !root.join("worker/result.json").exists(),
            "Binding refusal published an execution result"
        );
        let error = String::from_utf8(read_regular(
            &root.join("worker/error.txt"),
            32768,
            Some(&root),
        )?)?;
        ensure!(
            error.contains(reason),
            "Binding fixture wrong refusal: {error}"
        );
    } else {
        ensure!(stopped.exit_code == 0, "Binding fixture worker failed");
        let mut result: Value = serde_json::from_slice(&read_regular(
            &root.join("worker/result.json"),
            MAX_RESULT,
            Some(&root),
        )?)?;
        request
            .verify_result(&result, &expected, Some(persona))
            .map_err(anyhow::Error::msg)?;
        verify_artifacts(&root.join("worker"), &result["execution"]["artifacts"])?;
        ensure!(
            result["execution"]["guest_entry_return"] == 42,
            "Binding fixture did not execute its dependencies"
        );
        if case == "parent-options" {
            result["input_receipt"]["invocation"]["all_exports"] = true.into();
            save_new(
                &root.join("parent-rejected.json"),
                &bounded_json(&result, MAX_RESULT)?,
            )?;
            ensure!(
                request
                    .verify_result(&result, &expected, Some(persona))
                    .is_err(),
                "Parent accepted substituted options"
            );
        } else if case == "parent-artifact" {
            result["execution"]["artifacts"] =
                json!([{"filename":"escape.bin","sha256":"a".repeat(64),"size":4}]);
            save_new(
                &root.join("parent-rejected.json"),
                &bounded_json(&result, MAX_RESULT)?,
            )?;
            ensure!(
                verify_artifacts(&root.join("worker"), &result["execution"]["artifacts"]).is_err(),
                "Parent accepted substituted artifact"
            );
        }
    }
    ensure!(
        !root.join("manifest.json").exists(),
        "Fixture published a production manifest"
    );
    let receipt = json!({"schema":1,"case":case,"architecture":architecture,"verified":true,"worker_exit":stopped.exit_code,"cleanup":"restored","request_sha256":expected});
    save_new(
        &root.join("binding-verification.json"),
        &bounded_json(&receipt, MAX_REQUEST)?,
    )?;
    Ok(receipt)
}
