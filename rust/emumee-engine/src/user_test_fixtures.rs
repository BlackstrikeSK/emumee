//! Emit the exact source-tested input bytes for later contained CLI controls.
use emumee_core::user_input::Request;

pub(crate) fn execution(label: &str, result: &crate::Execution) {
    if label.contains("-m4-") && matches!(result.completion_reason, "entry_return" | "process_exit")
    {
        assert!(
            result.api_events.iter().all(|event| !event.pending),
            "Successful M4 execution retains pending API events: {label}"
        );
    }
    let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") else {
        return;
    };
    let path = std::path::PathBuf::from(root)
        .join(label)
        .join("source-execution.json");
    let mut value = serde_json::to_value(result).unwrap();
    for field in ["engine_seconds", "instructions_per_second"] {
        value.as_object_mut().unwrap().remove(field);
    }
    let bytes = serde_json::to_vec_pretty(&value).unwrap();
    if path.exists() {
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "Preserve differing source execution: {}",
            path.display()
        );
    } else {
        std::fs::write(path, bytes).unwrap();
    }
}

pub(crate) fn fixture(
    label: &str,
    request: &Request,
    bytes: &[u8],
    staged: &[Vec<u8>],
    persona: Option<&[u8]>,
) {
    let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") else {
        return;
    };
    let path = std::path::PathBuf::from(root).join(label);
    std::fs::create_dir_all(&path).unwrap();
    let save = |name: &str, data: &[u8]| {
        let destination = path.join(name);
        if destination.exists() {
            assert_eq!(
                std::fs::read(&destination).unwrap(),
                data,
                "Preserve differing fixture: {}",
                destination.display()
            );
        } else {
            std::fs::write(destination, data).unwrap();
        }
    };
    save(&request.module_name, bytes);
    assert_eq!(request.staged.len(), staged.len());
    let files = request
        .staged
        .iter()
        .zip(staged)
        .enumerate()
        .map(|(index, (file, bytes))| {
            let source = format!("input-{index:04}.bin");
            save(&source, bytes);
            serde_json::json!({"kind": file.kind, "guest_path": file.guest_path, "source": source})
        })
        .collect::<Vec<_>>();
    save(
        "inputs.json",
        &serde_json::to_vec(
            &serde_json::json!({"schema":1, "files":files, "invocation":request.invocation}),
        )
        .unwrap(),
    );
    save(
        "arguments.json",
        &serde_json::to_vec(&request.arguments).unwrap(),
    );
    save("limits.json", &serde_json::to_vec(&serde_json::json!({"max_instructions":request.max_instructions, "timeout_us":request.timeout_us})).unwrap());
    if let Some(persona) = persona {
        save("persona.json", persona);
    }
}
