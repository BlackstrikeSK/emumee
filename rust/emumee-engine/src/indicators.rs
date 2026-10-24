//! The only enabled source in this slice is a compiler-owned settled root.
//! Capture selection never changes guest instructions, permissions or status.
use super::*;
use emumee_core::{
    indicator_fixture::{self, Case},
    memory_observation::{self, Coverage, Omission, Receipt},
    memory_strings::{Capture, Options, Report},
    report_bundle::digest,
};
pub(super) struct Prepared {
    case: Case,
}
pub(super) struct State {
    capture: Capture,
    receipt: Receipt,
}

pub(super) fn install(
    engine: &mut NativeEngine,
    prepared: Prepared,
    pe: &PeImage,
    input: &[u8],
    base: u64,
) -> Result<()> {
    configured::require_unpublished(engine.get_data())?;
    ensure!(
        engine.get_data().indicators.is_none()
            && engine.get_data().capture.is_none()
            && engine.get_data().apis.captures.items.is_empty(),
        "Indicator policy already installed or mixed with another capture role"
    );
    ensure!(
        pe.image_size as usize == indicator_fixture::IMAGE_BYTES
            && (pe.sample.kind == emumee_core::pe::Kind::Driver) == prepared.case.kernel(),
        "Closed indicator target mismatch"
    );
    let case = prepared.case;
    engine.get_data_mut().indicators = Some(State {
        capture: Capture::new(if case.enabled() {
            Options::default()
        } else {
            Options::disabled()
        }),
        receipt: Receipt {
            version: memory_observation::VERSION.into(),
            case,
            source: indicator_fixture::SOURCE.into(),
            coverage: Coverage::Disabled,
            all_guest_memory_complete: false,
            enabled: case.enabled(),
            input_sha256: digest(input),
            initial_image_sha256: String::new(),
            settled_image_sha256: None,
            initial_patches_absent: false,
            runtime_patches_verified: false,
            capture_sha256: String::new(),
            image_base: base,
            image_bytes: pe.image_size as u64,
            read_limit: case.read_limit(),
            scan_limit: case.scan_limit() as u64,
            read_reserved_bytes: 0,
            read_bytes: 0,
            selected_bytes: 0,
            boundary_instructions: 0,
            boundary_pc: 0,
            retained_snapshot: false,
            omissions: Vec::new(),
        },
    });
    Ok(())
}
pub(super) fn materialized(engine: &mut Unicorn<Trace>, base: u64, image: &[u8]) {
    if let Some(state) = engine.get_data_mut().indicators.as_mut() {
        if state.receipt.image_base == base {
            state.receipt.initial_image_sha256 = digest(image);
            state.receipt.initial_patches_absent =
                state.receipt.case.patches().iter().all(|(rva, bytes)| {
                    image
                        .get(*rva..*rva + bytes.len())
                        .is_some_and(|part| part.iter().all(|byte| *byte == 0))
                });
        }
    }
}
pub(super) fn settled(engine: &mut Unicorn<Trace>, pc: u64) {
    let Some(mut state) = engine.get_data_mut().indicators.take() else {
        return;
    };
    state.receipt.boundary_instructions = engine.get_data().instructions;
    state.receipt.boundary_pc = pc;
    if state.receipt.enabled {
        observe(engine, &mut state);
    }
    engine.get_data_mut().indicators = Some(state);
}
fn observe(engine: &mut Unicorn<Trace>, state: &mut State) {
    let r = &mut state.receipt;
    r.coverage = Coverage::Omitted;
    if !engine
        .get_data()
        .apis
        .memory
        .allows(r.image_base, r.image_bytes, Permissions::READ)
    {
        r.omissions.push(Omission::RootNotReadable);
        return;
    }
    if r.image_bytes > r.read_limit {
        r.omissions.push(Omission::ReadBudget);
        return;
    }
    // One bounded physical read of a fully permitted root. The same actual buffer
    // is borrowed by the scanner and optionally moved into the legacy catalog.
    r.read_reserved_bytes = r.image_bytes;
    let mut bytes = vec![0; r.image_bytes as usize];
    if engine.mem_read(r.image_base, &mut bytes).is_err() {
        r.omissions.push(Omission::RootReadFailed);
        return;
    }
    r.read_bytes = bytes.len() as u64;
    r.settled_image_sha256 = Some(digest(&bytes));
    r.runtime_patches_verified =
        r.case.patches().iter().all(|(rva, payload)| {
            bytes.get(*rva..*rva + payload.len()) == Some(payload.as_slice())
        });
    let selected = bytes.len().min(r.scan_limit as usize);
    if state
        .capture
        .scan_memory(&bytes[..selected], indicator_fixture::SOURCE, r.image_base)
        .is_err()
    {
        r.omissions.push(Omission::ScannerSourceRefused);
    } else {
        r.selected_bytes = selected as u64;
        r.coverage = if selected < bytes.len() {
            r.omissions.push(Omission::ScanProfileLimit);
            Coverage::SelectedRootPrefix
        } else {
            Coverage::CompleteSelectedRoot
        };
    }
    if r.case.retain() {
        let catalog = &mut engine.get_data_mut().apis.captures;
        catalog.add(
            bytes,
            ArtifactKind::MemorySnapshot,
            indicator_fixture::SOURCE,
            "",
        );
        r.retained_snapshot = catalog
            .items
            .iter()
            .any(|item| Some(item.sha256.as_str()) == r.settled_image_sha256.as_deref());
    }
}
pub(super) fn take(engine: &mut Unicorn<Trace>) -> (Option<Report>, Option<Receipt>) {
    let Some(mut state) = engine.get_data_mut().indicators.take() else {
        return (None, None);
    };
    let capture = state.capture.into_report();
    let value =
        serde_json::to_value(&capture).expect("Bounded scalar indicator report serialization");
    state.receipt.capture_sha256 =
        memory_observation::capture_hash(&value).expect("Typed default scanner report is valid");
    (Some(capture), Some(state.receipt))
}
/// Receives the worker's actual staged bytes. Exact compiler recipe equality is
/// required before preparing this private policy; no program is regenerated for execution.
pub fn run(architecture: Architecture, case: Case, input: &[u8]) -> Result<Execution> {
    ensure!(
        input == case.input(architecture),
        "Closed indicator staged input mismatch"
    );
    run_generated_with_fixture_configuration(
        input,
        &[],
        1000,
        30_000_000,
        GeneratedConfiguration {
            indicators: Some(Prepared { case }),
            ..Default::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_native_and_kernel_stores_feed_borrowed_settled_bytes_and_optional_snapshot() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for case in Case::ALL {
                let input = case.input(architecture);
                let execution = run(architecture, case, &input).unwrap();
                assert_eq!(execution.guest_entry_return, Some(17));
                assert_eq!(execution.completion_reason, "entry_return");
                assert!(execution.error.is_none());
                let json = serde_json::to_value(&execution).unwrap();
                assert!(
                    memory_observation::valid_execution(&json),
                    "{architecture:?}/{case:?}"
                );
                let receipt = execution.memory_string_sources.as_ref().unwrap();
                assert!(receipt.initial_patches_absent);
                if case.enabled()
                    && !case.read_denied()
                    && case.read_limit() >= indicator_fixture::IMAGE_BYTES as u64
                {
                    assert!(receipt.runtime_patches_verified);
                    assert_ne!(
                        receipt.initial_image_sha256,
                        receipt.settled_image_sha256.as_deref().unwrap()
                    );
                }
                let expected = usize::from(
                    case.enabled()
                        && !case.read_denied()
                        && case.read_limit() >= indicator_fixture::IMAGE_BYTES as u64
                        && case.scan_limit() == indicator_fixture::IMAGE_BYTES,
                ) * 4;
                assert_eq!(
                    execution.memory_strings.as_ref().unwrap().matches().len(),
                    expected,
                    "{architecture:?}/{case:?}"
                );
                assert_eq!(execution.artifacts.len(), usize::from(case.retain()));
                if case.retain() {
                    let pe = PeImage::parse(&input, "owned.pe").unwrap();
                    let mut golden = pe.materialize(&input, pe.image_base).unwrap();
                    for (rva, payload) in case.patches() {
                        golden[rva..rva + payload.len()].copy_from_slice(&payload);
                    }
                    assert_eq!(execution.artifacts[0].data, golden);
                }
            }
        }
    }
    #[test]
    fn typed_extension_refuses_changed_report_source_budget_and_hash_authority() {
        let case = Case::NativeNone;
        let result = run(Architecture::X64, case, &case.input(Architecture::X64)).unwrap();
        let original = serde_json::to_value(&result).unwrap();
        for (field, value) in [
            ("source", serde_json::json!("memory:forged")),
            ("all_guest_memory_complete", serde_json::json!(true)),
            ("read_bytes", serde_json::json!(0)),
            ("capture_sha256", serde_json::json!("0".repeat(64))),
        ] {
            let mut altered = original.clone();
            altered["memory_string_sources"][field] = value;
            assert!(!memory_observation::valid_execution(&altered), "{field}");
        }
        let mut altered = original.clone();
        altered["memory_strings"]["matches"][0]["offset"] = serde_json::json!(0);
        assert!(!memory_observation::valid_execution(&altered));
        let mut altered = original.clone();
        altered["memory_string_sources"]["unknown"] = serde_json::json!(true);
        assert!(!memory_observation::valid_execution(&altered));
        assert!(!memory_observation::summary_matches(
            &serde_json::json!({}),
            &original
        ));
        let mut bad = case.input(Architecture::X64);
        bad[0] ^= 1;
        assert!(run(Architecture::X64, case, &bad).is_err());
    }
    #[test]
    fn old_roles_omit_extension_and_publication_prevents_policy_replacement() {
        let ordinary = run_fixture(Architecture::X64, 17, 1000).unwrap();
        let json = serde_json::to_value(ordinary).unwrap();
        assert!(
            json.get("memory_strings").is_none() && json.get("memory_string_sources").is_none()
        );
        let mut engine = new_engine(Architecture::X64).unwrap();
        let input = Case::Kernel.input(Architecture::X64);
        let pe = PeImage::parse(&input, "owned.sys").unwrap();
        engine.get_data_mut().instructions = 1;
        assert!(
            install(
                &mut engine,
                Prepared { case: Case::Kernel },
                &pe,
                &input,
                pe.image_base
            )
            .is_err()
        );
    }
}
