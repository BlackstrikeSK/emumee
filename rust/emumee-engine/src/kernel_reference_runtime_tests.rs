use super::*;
use emumee_core::provider::{RelocatedCodeSection, RelocatedCodeView};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const SHADOW_BASE: u64 = 0xffff_f800_1000_0000;
const WORD: u64 = 0x1_8000_1234;

fn generated_projection() -> RelocatedCodeView {
    let mut code = vec![0x90; 512];
    code[0x100..0x108].copy_from_slice(&WORD.to_le_bytes());
    RelocatedCodeView {
        source_sha256: "a".repeat(64),
        source_size: 4096,
        preferred_base: 0x1_4000_0000,
        target_base: SHADOW_BASE,
        image_size: 0x4000,
        sections: vec![RelocatedCodeSection {
            name: ".text".into(),
            rva: 0x1000,
            bytes: code,
        }],
    }
}

fn generated_reader() -> Vec<u8> {
    let mut image = counted_driver(Architecture::X64, 1);
    // mov rax, shadow word; mov rax, [rax]; ret.
    let mut code = vec![0x48, 0xb8];
    code.extend((SHADOW_BASE + 0x1100).to_le_bytes());
    code.extend([0x48, 0x8b, 0x00, 0xc3]);
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    image
}

#[test]
fn generated_driver_reads_reference_after_provider_setup_before_entry() {
    let execution = run_generated_with_fixture_configuration(
        &generated_reader(),
        &[],
        100,
        1_000_000,
        GeneratedConfiguration {
            kernel_reference: Some(KernelReferenceInput::Generated(generated_projection())),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(execution.completion_reason, "entry_return");
    assert_eq!(execution.guest_entry_return, Some(WORD));
    let mapping = execution.kernel_reference.unwrap();
    assert_eq!(mapping.target_base, SHADOW_BASE);
    assert!(mapping.read_only && mapping.non_executable);
    assert!(!mapping.provider_dispatch_replaced && !mapping.protected_data_replaced);
    assert!(!mapping.reference_execution_admitted && !mapping.reference_instructions_executed);
}

#[test]
fn pinned_runner_refuses_unverified_reference_before_guest_execution() {
    assert!(run_counted_driver_with_pinned_kernel_reference(&[0; 64], 1, 100).is_err());
    assert!(run_counted_driver_with_pinned_kernel_reference(&[], 1, 100).is_err());
}

#[test]
fn submitted_driver_reads_back_fixed_tcg_buffer_and_executes_generated_guest() {
    let execution = run_submitted_driver(
        &counted_driver(Architecture::X64, 1),
        "CaseService",
        100,
        1_000_000,
    )
    .unwrap();
    assert_eq!(
        execution.tcg_buffer_size,
        Some(tcg::SUBMITTED_DRIVER_BUFFER_BYTES)
    );
    assert_eq!(execution.completion_reason, "entry_return");
    assert_eq!(execution.guest_entry_return, Some(1));
    assert!(execution.instruction_count > 0);
}

struct BrokerSpy {
    drops: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}
impl emumee_core::broker::Client for BrokerSpy {
    fn call(
        &mut self,
        _operation: emumee_core::broker::Operation,
    ) -> std::result::Result<emumee_core::broker::Reply, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err("Generated counted driver does not make a broker call".into())
    }
}
impl Drop for BrokerSpy {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn submitted_generated_driver_retains_and_drops_broker_with_reference_authority() {
    let drops = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let make_broker = || {
        Box::new(BrokerSpy {
            drops: Arc::clone(&drops),
            calls: Arc::clone(&calls),
        }) as Box<dyn emumee_core::broker::Client>
    };
    let execution = run_submitted_driver_with_reference_and_broker(
        &counted_driver(Architecture::X64, 1),
        "EmumeeFixture",
        100,
        1_000_000,
        None,
        Some(make_broker()),
    )
    .unwrap();
    assert_eq!(execution.completion_reason, "entry_return");
    assert_eq!(execution.guest_entry_return, Some(1));
    assert!(execution.kernel_reference.is_none());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // The test-only generated projection exercises reference plus submitted
    // broker authority through the same configured engine path. Production
    // callers can reach this path only with the exact pinned NT reference.
    let execution = run_generated_with_fixture_configuration(
        &generated_reader(),
        &[],
        100,
        1_000_000,
        GeneratedConfiguration {
            submitted_driver_service: Some("EmumeeFixture".into()),
            kernel_reference: Some(KernelReferenceInput::Generated(generated_projection())),
            broker: Some(make_broker()),
            capture: Some(capture::Prepared::submitted()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(execution.completion_reason, "entry_return");
    assert_eq!(execution.guest_entry_return, Some(WORD));
    assert!(execution.kernel_reference.is_some());
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn submitted_driver_installs_literal_clock_persona_and_service_identity() {
    let persona = emumee_core::fixtures::configured_document(
        emumee_core::fixtures::ConfiguredFixture::Kernel,
    );
    let execution = run_submitted_driver_with_persona_and_reference_and_broker(
        &counted_driver(Architecture::X64, 1),
        "CaseService",
        100,
        1_000_000,
        Some(&persona),
        None,
        None,
    )
    .unwrap();
    assert_eq!(execution.completion_reason, "entry_return");
    assert_eq!(execution.guest_entry_return, Some(1));
    let receipt = execution.configuration.unwrap();
    assert!(receipt.initialized);
    assert!(!receipt.generated_only);
    assert_eq!(receipt.windows_build, 26100);
    assert_eq!(
        receipt.guest_image_path.as_deref(),
        Some(r"C:\Windows\System32\drivers\CaseService.sys")
    );
    assert!(
        receipt
            .installed_components
            .contains(&"submitted_service_identity")
    );
    assert!(
        !receipt
            .pending
            .iter()
            .any(|row| row.path == "driver_entry.registry_path")
    );
}

#[test]
fn submitted_driver_refuses_unresolved_persona_clock_before_guest() {
    let mut persona: serde_json::Value =
        serde_json::from_slice(&emumee_core::fixtures::configured_document(
            emumee_core::fixtures::ConfiguredFixture::Kernel,
        ))
        .unwrap();
    persona["clock_utc"] = serde_json::Value::Null;
    let persona = serde_json::to_vec(&persona).unwrap();
    assert!(
        run_submitted_driver_with_persona_and_reference_and_broker(
            &counted_driver(Architecture::X64, 1),
            "CaseService",
            100,
            1_000_000,
            Some(&persona),
            None,
            None,
        )
        .is_err()
    );
}

#[test]
fn submitted_persona_reference_and_broker_share_one_generated_execution() {
    let persona = emumee_core::fixtures::configured_document(
        emumee_core::fixtures::ConfiguredFixture::Kernel,
    );
    let validated = emumee_core::fullpersona::decode(
        &persona,
        &emumee_core::fullpersona::ResolveContext::default(),
    )
    .unwrap();
    let prepared = configured::Prepared::new(
        validated,
        configured::Request {
            architecture: Architecture::X64,
            kernel: true,
            initial_processor: 0,
            process: None,
            budget: 100,
            timeout_us: 1_000_000,
        },
    )
    .unwrap()
    .bind_submitted_service("CaseService")
    .unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let execution = run_generated_with_fixture_configuration(
        &generated_reader(),
        &[],
        100,
        1_000_000,
        GeneratedConfiguration {
            submitted_driver_service: Some("CaseService".into()),
            submitted_persona_authorized: true,
            kernel_reference: Some(KernelReferenceInput::Generated(generated_projection())),
            broker: Some(Box::new(BrokerSpy {
                drops: Arc::clone(&drops),
                calls: Arc::clone(&calls),
            })),
            configured: Some(prepared),
            capture: Some(capture::Prepared::submitted()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(execution.completion_reason, "entry_return");
    assert_eq!(execution.guest_entry_return, Some(WORD));
    assert_eq!(execution.configuration.unwrap().windows_build, 26100);
    assert!(execution.kernel_reference.is_some());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
