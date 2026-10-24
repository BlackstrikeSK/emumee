//! Borrow real UTF16 heap units at successful ldstr and actual call transitions.
//! Capture refusal changes only observation diagnostics, never guest values/EH.
use super::{Heap, Value};
use emumee_core::{
    managed_indicator_fixture::Case,
    managed_observation::{self, Event, Kind, Outcome, Receipt},
    memory_strings::{Capture, Error, Options, Report},
    report_bundle::digest,
};
pub(super) struct Prepared {
    pub case: Case,
    pub input_sha256: String,
}
pub(super) struct Observer {
    capture: Capture,
    receipt: Receipt,
    current_instruction: u64,
}
impl Observer {
    pub fn new(prepared: Prepared) -> Self {
        let case = prepared.case;
        Self {
            capture: Capture::new(if case.enabled() {
                Options::default()
            } else {
                Options::disabled()
            }),
            current_instruction: 0,
            receipt: Receipt {
                version: managed_observation::VERSION.into(),
                case,
                enabled: case.enabled(),
                all_managed_strings_complete: false,
                all_guest_memory_complete: false,
                input_sha256: prepared.input_sha256,
                capture_sha256: String::new(),
                event_sources: ["managed_ldstr", "managed_argument", "managed_return"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                events_seen: 0,
                events_omitted: 0,
                events: vec![],
                source_utf16_bytes_observed: 0,
                max_source_utf16_bytes: managed_observation::MAX_SOURCE_UTF16_BYTES,
                boundary_instructions: 0,
                boundary_method: 0,
                boundary_offset: 0,
                omitted_sources: 0,
            },
        }
    }
    pub fn boundary(&mut self, count: u64) {
        self.current_instruction = count;
    }
    pub fn literal(&mut self, heap: &Heap, reference: u32, token: u32, count: u64) {
        self.observe(
            heap,
            Value::StringRef(reference),
            Kind::Literal,
            format!("managed_ldstr:0x{token:08x}"),
            Some(token),
            count,
        );
    }
    pub fn arguments(&mut self, heap: &Heap, values: &[Value], name: &str, count: u64) {
        if !self.receipt.enabled {
            return;
        }
        for value in values {
            if matches!(value, Value::StringRef(_)) {
                self.observe(
                    heap,
                    *value,
                    Kind::Argument,
                    format!("managed_argument:{name}"),
                    None,
                    count,
                );
            }
        }
    }
    pub fn returned(&mut self, heap: &Heap, value: Option<Value>, name: &str, count: u64) {
        if let Some(value @ Value::StringRef(_)) = value {
            self.observe(
                heap,
                value,
                Kind::Return,
                format!("managed_return:{name}"),
                None,
                count,
            );
        }
    }
    pub fn framework_arguments(&mut self, heap: &Heap, values: &[Value], name: &str) {
        self.arguments(heap, values, name, self.current_instruction);
    }
    pub fn framework_return(&mut self, heap: &Heap, value: Option<Value>, name: &str) {
        self.returned(heap, value, name, self.current_instruction);
    }
    fn observe(
        &mut self,
        heap: &Heap,
        value: Value,
        kind: Kind,
        source: String,
        token: Option<u32>,
        count: u64,
    ) {
        if !self.receipt.enabled {
            return;
        }
        let Value::StringRef(reference) = value else {
            return;
        };
        self.receipt.events_seen += 1;
        let mut event = Event {
            kind,
            source,
            reference,
            token,
            instruction_count: count,
            utf16_units: 0,
            utf16_sha256: None,
            outcome: Outcome::InvalidReference,
        };
        if let Ok(units) = heap.string(reference) {
            event.utf16_units = units.len() as u64;
            let bytes = units.len() as u64 * 2;
            if bytes
                > managed_observation::MAX_SOURCE_UTF16_BYTES
                    - self.receipt.source_utf16_bytes_observed
            {
                event.outcome = Outcome::ObserverReadBudget;
            } else {
                self.receipt.source_utf16_bytes_observed += bytes;
                event.utf16_sha256 = Some(managed_observation::utf16_hash(units));
                event.outcome = match self.capture.scan_managed_utf16(units, &event.source) {
                    Ok(()) => Outcome::Scanned,
                    Err(Error::UnpairedSurrogatePending) => Outcome::UnpairedSurrogatePending,
                    Err(Error::SourceLimit) => Outcome::SourceLimit,
                    Err(_) => Outcome::ScannerRefused,
                };
            }
        }
        if event.outcome != Outcome::Scanned {
            self.receipt.omitted_sources += 1;
        }
        if self.receipt.events.len() < managed_observation::MAX_EVENTS {
            self.receipt.events.push(event);
        } else {
            self.receipt.events_omitted += 1;
        }
    }
    pub fn finish(mut self, count: u64, method: u32, offset: u32) -> (Report, Receipt) {
        self.receipt.boundary_instructions = count;
        self.receipt.boundary_method = method;
        self.receipt.boundary_offset = offset;
        let capture = self.capture.into_report();
        let value = serde_json::to_value(&capture).expect("Bounded typed string report");
        self.receipt.capture_sha256 = emumee_core::memory_observation::capture_hash(&value)
            .expect("Typed scanner report valid");
        (capture, self.receipt)
    }
}
pub fn run(
    architecture: emumee_core::pe::Architecture,
    case: Case,
    input: &[u8],
) -> anyhow::Result<super::Execution> {
    anyhow::ensure!(
        input == case.input(architecture),
        "Closed managed indicator staged input mismatch"
    );
    super::run_image(
        architecture,
        input,
        case.budget(),
        std::time::Duration::from_secs(30),
        Some(Prepared {
            case,
            input_sha256: digest(input),
        }),
    )
}
