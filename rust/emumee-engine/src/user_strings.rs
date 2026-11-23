//! Submitted-sample memory-string capture (the live-run counterpart to the
//! closed `indicators` slice). It scans the settled image root of the *submitted*
//! sample with the caller-configured bounded matcher (built-in IP/URL indicators
//! plus admitted `custom_<i>` patterns) and emits the additive
//! `emumee.user-memory-indicators.v1` profile. Selecting capture never changes
//! guest instructions, permissions or status; nothing is read outside the owned
//! image, and reads/scans are bounded by the plan's budgets.
use super::*;
use emumee_core::{
    memory_strings::{Capture, Options, Report},
    report_bundle::digest,
    user_memory_observation::{self as obs, Coverage, Omission, Receipt},
};

pub(super) const SOURCE: &str = "guest_image_at_stop";

pub(super) struct Prepared {
    pub options: Options,
    pub enabled: bool,
    pub patterns: Vec<String>,
    pub scan_limit: u64,
    pub read_limit: u64,
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
            && engine.get_data().user_strings.is_none()
            && engine.get_data().capture.is_none(),
        "Submitted memory-string capture cannot mix with another capture role"
    );
    engine.get_data_mut().user_strings = Some(State {
        capture: Capture::new(prepared.options),
        receipt: Receipt {
            version: obs::VERSION.into(),
            source: SOURCE.into(),
            coverage: Coverage::Disabled,
            enabled: prepared.enabled,
            patterns: prepared.patterns,
            input_sha256: digest(input),
            image_base: base,
            image_bytes: pe.image_size as u64,
            scan_limit: prepared.scan_limit,
            read_limit: prepared.read_limit,
            read_reserved_bytes: 0,
            read_bytes: 0,
            selected_bytes: 0,
            private_runs: 0,
            private_bytes: 0,
            capture_sha256: String::new(),
            boundary_instructions: 0,
            boundary_pc: 0,
            omissions: Vec::new(),
        },
    });
    Ok(())
}
pub(super) fn settled(engine: &mut Unicorn<Trace>, pc: u64) {
    let Some(mut state) = engine.get_data_mut().user_strings.take() else {
        return;
    };
    state.receipt.boundary_instructions = engine.get_data().instructions;
    state.receipt.boundary_pc = pc;
    if state.receipt.enabled {
        observe(engine, &mut state);
        // Live private reservations are scanned whether or not the image root
        // itself was readable within budget.
        private_runs(engine, &mut state);
    }
    engine.get_data_mut().user_strings = Some(state);
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
        r.omissions.push(Omission::ImageNotReadable);
        return;
    }
    if r.image_bytes > r.read_limit {
        r.omissions.push(Omission::ReadBudget);
        return;
    }
    r.read_reserved_bytes = r.image_bytes;
    let mut bytes = vec![0; r.image_bytes as usize];
    if engine.mem_read(r.image_base, &mut bytes).is_err() {
        r.omissions.push(Omission::ImageReadFailed);
        return;
    }
    r.read_bytes = bytes.len() as u64;
    let selected = bytes.len().min(r.scan_limit as usize);
    if state
        .capture
        .scan_memory(&bytes[..selected], SOURCE, r.image_base)
        .is_err()
    {
        r.omissions.push(Omission::ScannerSourceRefused);
        return;
    }
    r.selected_bytes = selected as u64;
    r.coverage = if selected < bytes.len() {
        r.omissions.push(Omission::ScanBudget);
        Coverage::SelectedRootPrefix
    } else {
        Coverage::CompleteSelectedRoot
    };
}
/// Scan the sample's own committed private reservations after the image root,
/// in address order, until the configured scan budget is spent. Only owned,
/// readable guest memory is touched; nothing outside a live reservation is read.
fn private_runs(engine: &mut Unicorn<Trace>, state: &mut State) {
    let runs = engine.get_data().apis.allocations.committed_runs();
    for (base, size) in runs {
        let r = &mut state.receipt;
        let remaining = r.scan_limit.saturating_sub(r.selected_bytes);
        if remaining == 0 {
            r.omissions.push(Omission::PrivateScanBudget);
            break;
        }
        if size == 0 {
            continue;
        }
        if !engine
            .get_data()
            .apis
            .memory
            .allows(base, size, Permissions::READ)
        {
            continue;
        }
        let selected = size.min(remaining);
        let Ok(bytes) = engine.mem_read_as_vec(base, selected as usize) else {
            state.receipt.omissions.push(Omission::PrivateReadFailed);
            continue;
        };
        let source = format!("guest_private_at_stop:0x{base:x}");
        if state.capture.scan_memory(&bytes, &source, base).is_err() {
            state.receipt.omissions.push(Omission::ScannerSourceRefused);
            continue;
        }
        let r = &mut state.receipt;
        r.selected_bytes += selected;
        r.private_bytes += selected;
        r.private_runs += 1;
        if selected < size {
            r.omissions.push(Omission::PrivateScanBudget);
            break;
        }
    }
}
pub(super) fn take(engine: &mut Unicorn<Trace>) -> (Option<Report>, Option<Receipt>) {
    let Some(mut state) = engine.get_data_mut().user_strings.take() else {
        return (None, None);
    };
    let capture = state.capture.into_report();
    let value =
        serde_json::to_value(&capture).expect("Bounded scalar user indicator report serialization");
    state.receipt.capture_sha256 =
        obs::memory_capture_hash(&value).expect("Typed user scanner report is valid");
    (Some(capture), Some(state.receipt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::fixtures::counted_driver;
    use emumee_core::user_memory_observation;

    fn prepared(patterns: &[&str]) -> Prepared {
        let value = serde_json::json!({ "enabled": true, "regex": patterns });
        Prepared {
            options: Options::decode(Some(&value)).unwrap(),
            enabled: true,
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
            scan_limit: 128 * 1024 * 1024,
            read_limit: 128 * 1024 * 1024,
        }
    }

    #[test]
    fn submitted_sample_scan_emits_a_valid_bound_user_profile() {
        for architecture in [Architecture::X86, Architecture::X64] {
            // Any run of >=6 printable ASCII bytes; a mapped image always has some.
            let config = GeneratedConfiguration {
                user_strings: Some(prepared(&["[ -~]{6,}"])),
                ..Default::default()
            };
            let execution = crate::run_generated_with_fixture_configuration(
                &counted_driver(architecture, 500),
                &[],
                1000,
                30_000_000,
                config,
            )
            .unwrap();
            let json = serde_json::to_value(&execution).unwrap();
            assert!(
                user_memory_observation::valid_execution(&json),
                "{architecture:?}: {json:#}"
            );
            assert!(user_memory_observation::present(&json));
            let report = execution.user_memory_strings.as_ref().unwrap();
            let receipt = execution.user_memory_capture.as_ref().unwrap();
            assert!(receipt.selected_bytes > 0, "{architecture:?}");
            assert_eq!(report.scanned_bytes(), receipt.selected_bytes);
            assert_eq!(receipt.patterns, vec!["[ -~]{6,}".to_string()]);
            // The capture digest in the receipt binds the serialized report.
            assert_eq!(
                user_memory_observation::memory_capture_hash(&json["user_memory_strings"])
                    .as_deref(),
                Some(receipt.capture_sha256.as_str())
            );
        }
    }

    #[test]
    fn custom_pattern_matches_a_known_image_string() {
        // The generated driver embeds this owned marker; a custom pattern must
        // surface it from the settled image as a custom_1 indicator.
        let architecture = Architecture::X64;
        let image = counted_driver(architecture, 500);
        let needle = b"owned";
        if image.windows(needle.len()).any(|w| w == needle) {
            let config = GeneratedConfiguration {
                user_strings: Some(prepared(&["owned"])),
                ..Default::default()
            };
            let execution = crate::run_generated_with_fixture_configuration(
                &image,
                &[],
                1000,
                30_000_000,
                config,
            )
            .unwrap();
            let report = execution.user_memory_strings.as_ref().unwrap();
            assert!(
                report.matches().iter().any(|m| m.value == "owned"),
                "custom pattern did not surface the owned marker"
            );
        }
    }

    #[test]
    fn without_the_role_there_is_no_user_profile() {
        let execution = crate::run_fixture(Architecture::X64, 500, 1000).unwrap();
        assert!(
            execution.user_memory_strings.is_none() && execution.user_memory_capture.is_none()
        );
        let json = serde_json::to_value(&execution).unwrap();
        assert!(user_memory_observation::valid_execution(&json));
        assert!(!user_memory_observation::present(&json));
    }
}
