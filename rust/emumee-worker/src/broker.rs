//! Separate offline broker/client roles used to qualify the real process/IPC
//! boundary. Guest API integration builds on these endpoints.
use anyhow::{Context, Result, ensure};
use emumee_core::broker::{
    self, Config, Data, FrameReader, Operation, Probe, Reply, Request, Service,
};
use emumee_platform::windows::{open_pinned, open_pinned_journal, prepare_worker, read_regular};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, rc::Rc};
use std::{
    fs::File,
    io::Write,
    path::Path,
    time::{Duration, Instant},
};
#[derive(Clone, Copy)]
enum StreamPolicy {
    Fixture,
    Closed128,
}
fn checked_packet_end(current: u64, payload: usize) -> Result<u64> {
    ensure!(
        payload > 0 && payload <= broker::MAX_PACKET,
        "Closed plan packet size bound"
    );
    let end = current
        .checked_add(payload as u64)
        .and_then(|n| n.checked_add(4))
        .context("Closed plan stream byte overflow")?;
    ensure!(
        end <= broker::MAX_STREAM as u64,
        "Closed plan RPC stream bound exceeded"
    );
    Ok(end)
}
fn write_selected_packet(
    output: &mut File,
    value: &impl serde::Serialize,
    policy: StreamPolicy,
) -> Result<()> {
    if matches!(policy, StreamPolicy::Fixture) {
        return broker::write_packet(output, value).map_err(anyhow::Error::msg);
    }
    let raw = emumee_core::report_bundle::bounded_json(value, broker::MAX_PACKET)?;
    let _ = checked_packet_end(output.metadata()?.len(), raw.len())?;
    output.write_all(&(raw.len() as u32).to_le_bytes())?;
    output.write_all(&raw)?;
    output.flush()?;
    Ok(())
}
struct Rpc {
    requests: File,
    replies: File,
    reader: FrameReader,
    next: u32,
    stream_policy: StreamPolicy,
}
impl broker::Client for Rpc {
    fn call(&mut self, operation: Operation) -> Result<Reply, String> {
        ensure_rpc_bound(self.next)?;
        let id = self.next;
        self.next += 1;
        call_selected(
            &mut self.requests,
            &mut self.replies,
            &mut self.reader,
            Request {
                id,
                request: operation,
            },
            self.stream_policy,
        )
        .map_err(|e| format!("{e:#}"))
    }
}
fn ensure_rpc_bound(id: u32) -> Result<(), String> {
    if id > broker::MAX_CALLS {
        Err("Broker call bound exceeded".into())
    } else {
        Ok(())
    }
}
struct SharedRpc(Rc<RefCell<Rpc>>);
impl broker::Client for SharedRpc {
    fn call(&mut self, operation: Operation) -> Result<Reply, String> {
        broker::Client::call(&mut *self.0.borrow_mut(), operation)
    }
}

fn config(root: &Path, expected: &str) -> Result<Config> {
    let control = root.join("control");
    let raw = read_regular(&control.join("config.json"), 1024 * 1024, Some(&control))?;
    ensure!(
        format!("{:x}", Sha256::digest(&raw)) == expected,
        "Broker configuration hash changed"
    );
    let config: Config = serde_json::from_slice(&raw)?;
    ensure!(config.schema == 4, "Invalid broker configuration schema");
    config.fixture.validate().map_err(anyhow::Error::msg)?;
    Ok(config)
}
fn record(file: &mut File, event: Value, count: &mut usize, bytes: &mut usize) -> Result<()> {
    let mut raw = serde_json::to_vec(&event)?;
    raw.push(b'\n');
    ensure!(
        raw.len() <= emumee_core::broker_journal::MAX_RECORD_BYTES
            && *count < emumee_core::broker_journal::MAX_EVENTS,
        "Broker journal record limit"
    );
    *bytes = bytes
        .checked_add(raw.len())
        .context("Journal size overflow")?;
    ensure!(
        *bytes <= emumee_core::broker_journal::MAX_JOURNAL_BYTES,
        "Broker journal byte limit"
    );
    file.write_all(&raw)?;
    file.sync_data()?;
    *count += 1;
    Ok(())
}
pub fn server(root: &Path, expected: &str) -> Result<()> {
    let containment = serde_json::to_value(prepare_worker()?)?;
    let config = config(root, expected)?;
    let private = root.join("private");
    let service = if let Some(digest) = &config.fixture_document_sha256 {
        let raw = read_regular(
            &private.join("http-fixtures.json"),
            emumee_core::networkfixtures::MAX_FILE,
            Some(&private),
        )?;
        ensure!(
            format!("{:x}", Sha256::digest(&raw)) == *digest,
            "Private HTTP fixture hash changed"
        );
        Service::with_fixtures(
            emumee_core::networkfixtures::Fixtures::parse(&raw).map_err(anyhow::Error::msg)?,
        )
    } else {
        Service::new(Some(config.fixture)).map_err(anyhow::Error::msg)?
    };
    serve(
        root,
        containment,
        service,
        ServerSettings {
            cleanup_plan: &config.cleanup_plan,
            deadline: Duration::from_secs(30),
            fault: Some(config.probe),
            plan_fault: emumee_core::plan_runtime::Fault::None,
            binding: None,
            target_read_denied: None,
            persona_read_denied: None,
        },
    )
}
pub fn plan_server(root: &Path, expected: &str) -> Result<()> {
    let containment = serde_json::to_value(prepare_worker()?)?;
    let control = root.join("control");
    let raw = read_regular(&control.join("config.json"), 4096, Some(&control))?;
    ensure!(
        emumee_core::report_bundle::digest(&raw) == expected,
        "Plan broker config transport changed"
    );
    let request = read_regular(&control.join("request.json"), 4096, Some(&control))?;
    let config = emumee_core::plan_runtime::BrokerSession::parse(&raw, &request)
        .map_err(anyhow::Error::msg)?;
    let plan = read_regular(
        &control.join("plan.json"),
        emumee_core::analysis_plan::MAX_PLAN_BYTES,
        Some(&control),
    )?;
    ensure!(
        emumee_core::report_bundle::digest(&plan) == config.plan_sha256,
        "Broker plan binding changed"
    );
    let private = root.join("private");
    let fixtures = read_regular(
        &private.join("http-fixtures.json"),
        emumee_core::networkfixtures::MAX_FILE,
        Some(&private),
    )?;
    ensure!(
        emumee_core::report_bundle::digest(&fixtures) == config.fixture_sha256,
        "Private plan fixture binding changed"
    );
    let fixtures =
        emumee_core::networkfixtures::Fixtures::parse(&fixtures).map_err(anyhow::Error::msg)?;
    let target_denied = File::open(control.join("inputs/0000.bin"))
        .err()
        .is_some_and(|e| e.raw_os_error() == Some(5));
    let persona_denied = File::open(control.join("persona.json"))
        .err()
        .is_some_and(|e| e.raw_os_error() == Some(5));
    ensure!(
        target_denied && persona_denied,
        "Plan broker can read worker-owned target/persona"
    );
    let binding = json!({"event":"broker_started","mode":"offline_replay","role":"closed_plan_broker","config_sha256":expected,"request_sha256":config.request_sha256,"plan_sha256":config.plan_sha256,"fixture_sha256":config.fixture_sha256});
    serve(
        root,
        containment,
        Service::with_fixtures(fixtures),
        ServerSettings {
            cleanup_plan: &config.cleanup_plan,
            deadline: Duration::from_millis(config.deadline_ms),
            fault: None,
            plan_fault: emumee_core::plan_runtime::Request::parse(&request)
                .map_err(anyhow::Error::msg)?
                .fault,
            binding: Some(binding),
            target_read_denied: Some(target_denied),
            persona_read_denied: Some(persona_denied),
        },
    )
}

/// Private side of a generated general RPC check. The claim and fixture are
/// read from private/ under a separate offline SID; guest admission stays off.
pub(crate) fn general_server(root: &Path, expected_claim: &str, cleanup_plan: &Path) -> Result<()> {
    general_server_with_deadline(root, expected_claim, cleanup_plan, Duration::from_secs(30))
}

fn general_server_with_deadline(
    root: &Path,
    expected_claim: &str,
    cleanup_plan: &Path,
    deadline: Duration,
) -> Result<()> {
    use emumee_core::{
        general_broker_private_attestation::{Claim, MAX_CLAIM},
        report_bundle::digest,
    };
    let containment = serde_json::to_value(prepare_worker()?)?;
    let root = std::path::absolute(root)?;
    let private = root.join("private");
    let claim_raw = read_regular(&private.join("claim.json"), MAX_CLAIM, Some(&private))?;
    ensure!(
        digest(&claim_raw) == expected_claim,
        "General broker claim transport changed"
    );
    let claim = Claim::parse(&claim_raw).map_err(anyhow::Error::msg)?;
    let fixture = read_regular(
        &private.join("http-fixtures.json"),
        usize::try_from(claim.fixture.size)?,
        Some(&private),
    )?;
    let inspection = claim
        .inspect(&claim_raw, &fixture)
        .map_err(anyhow::Error::msg)?;
    let target_denied = File::open(root.join("control/inputs/0000.bin"))
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(5));
    let plan_denied = File::open(root.join("control/plan.json"))
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(5));
    let request_denied = File::open(root.join("control/request.json"))
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(5));
    ensure!(
        target_denied && plan_denied && request_denied,
        "General RPC broker can read public target or plan"
    );
    let ipc = root.join("ipc");
    let request_append_denied = std::fs::OpenOptions::new()
        .append(true)
        .open(ipc.join("requests.bin"))
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(5));
    let response_overwrite_denied = std::fs::OpenOptions::new()
        .write(true)
        .open(ipc.join("responses.bin"))
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(5));
    let ipc_creation_denied = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(ipc.join("injected.bin"))
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(5));
    ensure!(
        request_append_denied && response_overwrite_denied && ipc_creation_denied,
        "General RPC broker IPC permissions are too broad"
    );
    super::save_new(
        &root.join("broker/general-private-inspection.json"),
        &serde_json::to_vec(&json!({
            "schema":1,"role":"general_rpc_broker_v1","claim_sha256":expected_claim,
            "containment":containment,"inspection":inspection,"public_read_denied":true,
            "request_append_denied":request_append_denied,
            "response_overwrite_denied":response_overwrite_denied,
            "ipc_creation_denied":ipc_creation_denied,
            "guest_admission":false,"engine_applied":false,"guest_executed":false,
        }))?,
    )?;
    let fixtures =
        emumee_core::networkfixtures::Fixtures::parse(&fixture).map_err(anyhow::Error::msg)?;
    let start = claim
        .expected_journal_start(&claim_raw)
        .map_err(anyhow::Error::msg)?;
    let binding: Value = serde_json::from_slice(&start)?;
    serve(
        &root,
        containment,
        Service::with_fixtures(fixtures),
        ServerSettings {
            cleanup_plan: cleanup_plan
                .to_str()
                .context("Cleanup plan path not Unicode")?,
            deadline,
            fault: None,
            plan_fault: emumee_core::plan_runtime::Fault::None,
            binding: Some(binding),
            target_read_denied: Some(target_denied),
            persona_read_denied: None,
        },
    )
}

/// Generated Driver128's separate offline broker. It shares the verified
/// private fixture and bounded RPC service with the general probe, then
/// records the actual closed journal for the parent to pair with the guest
/// worker's independent execution receipt. The broker cannot attest guest
/// execution or turn this receipt into a general admission permit.
pub(crate) fn general_driver128_server(
    root: &Path,
    expected_claim: &str,
    cleanup_plan: &Path,
) -> Result<()> {
    use emumee_core::{
        broker_journal::MAX_JOURNAL_BYTES,
        general_broker_private_attestation::{Claim, MAX_CLAIM},
        report_bundle::digest,
    };
    // The parent job and worker deadline remain the outer lifetime guard.
    // The broker's own longer cap lets bounded driver execution make progress
    // without reusing the three-second RPC reply timeout as a run limit.
    general_server_with_deadline(
        root,
        expected_claim,
        cleanup_plan,
        Duration::from_secs(3_620),
    )?;
    let root = std::path::absolute(root)?;
    let private = root.join("private");
    let claim_raw = read_regular(&private.join("claim.json"), MAX_CLAIM, Some(&private))?;
    ensure!(
        digest(&claim_raw) == expected_claim,
        "Driver128 broker claim changed after RPC close"
    );
    let claim = Claim::parse(&claim_raw).map_err(anyhow::Error::msg)?;
    let journal = read_regular(
        &private.join("network-broker.journal"),
        MAX_JOURNAL_BYTES,
        Some(&private),
    )?;
    let (expected_start, recovered) = driver128_closed_journal(&claim, &claim_raw, &journal)?;
    let ready = read_regular(&root.join("broker/broker-ready.json"), 4096, Some(&root))?;
    let containment: Value = serde_json::from_slice(&ready)?;
    ensure!(
        containment["app_container"] == true
            && containment["job_object"] == true
            && containment["child_process_blocked"] == true
            && containment["network_capabilities"] == 0
            && containment["cleanup_plan_read_denied"] == true
            && containment["target_read_denied"] == true,
        "Driver128 broker ready containment differs"
    );
    super::save_new(
        &root.join("broker/driver128-broker-result.json"),
        &emumee_core::report_bundle::bounded_json(
            &json!({
                "schema":1,
                "role":"general_driver128_offline_broker_v1",
                "source_tree_sha256":env!("EMUMEE_BUILD_SOURCE_SHA256"),
                "claim_sha256":expected_claim,
                "request_sha256":claim.request_sha256,
                "journal_sha256":recovered.source_sha256,
                "journal_bytes":recovered.source_bytes,
                "journal_events":recovered.events.len(),
                "journal_start_sha256":digest(&expected_start),
                "rpc_closed":true,
                "containment":containment,
                "guest_admission":false,
                "engine_applied":false,
                "guest_executed":false,
            }),
            4096,
        )?,
    )?;
    Ok(())
}

fn driver128_closed_journal(
    claim: &emumee_core::general_broker_private_attestation::Claim,
    claim_raw: &[u8],
    journal: &[u8],
) -> Result<(Vec<u8>, emumee_core::broker_journal::Recovery)> {
    let expected_start = claim
        .expected_journal_start(claim_raw)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        journal.starts_with(&expected_start),
        "Driver128 broker journal lost claim-bound first record"
    );
    let recovered = emumee_core::broker_journal::recover(journal)?;
    ensure!(
        recovered.closed && recovered.stop_reason.is_none(),
        "Driver128 broker journal did not close cleanly"
    );
    Ok((expected_start, recovered))
}

#[cfg(test)]
mod driver128_broker_tests {
    use super::*;
    use emumee_core::{
        general_broker_private_attestation::{Claim, OPERATION, PROFILE},
        general_execution_commitment::BrokerPrivateFixture,
    };

    #[test]
    fn close_requires_claim_bound_first_record_and_complete_final_marker() {
        let hash = "0".repeat(64);
        let claim = Claim {
            schema: 1,
            profile: PROFILE.into(),
            operation: OPERATION.into(),
            execution_authorized: false,
            request_sha256: hash.clone(),
            resolved_plan_sha256: hash.clone(),
            fixture: BrokerPrivateFixture {
                index: 1,
                id: "offline".into(),
                size: 1,
                original_sha256: hash.clone(),
                canonical_sha256: hash.clone(),
                canonical_bytes: 1,
                bodies_sha256: hash,
            },
        };
        let raw = serde_json::to_vec(&claim).unwrap();
        let start = claim.expected_journal_start(&raw).unwrap();
        let journal = [start.as_slice(), b"{\"event\":\"broker_closed\"}\n"].concat();
        let (_, recovered) = driver128_closed_journal(&claim, &raw, &journal).unwrap();
        assert!(recovered.closed);
        assert_eq!(recovered.events.len(), 2);
        let mut changed = journal.clone();
        changed[0] ^= 1;
        assert!(driver128_closed_journal(&claim, &raw, &changed).is_err());
        assert!(driver128_closed_journal(&claim, &raw, &start).is_err());
        assert!(driver128_closed_journal(&claim, &raw, &journal[..journal.len() - 1]).is_err());
    }
}
pub(crate) fn plan_connection(root: &Path) -> Result<(Box<dyn broker::Client>, PlanClose)> {
    let ipc = root.join("ipc");
    let rpc = Rc::new(RefCell::new(Rpc {
        requests: open_pinned(&ipc.join("requests.bin"), &ipc, true)?,
        replies: open_pinned(&ipc.join("responses.bin"), &ipc, false)?,
        reader: FrameReader::default(),
        next: 1,
        stream_policy: StreamPolicy::Closed128,
    }));
    Ok((Box::new(SharedRpc(rpc.clone())), PlanClose(rpc)))
}
pub(crate) struct PlanClose(Rc<RefCell<Rpc>>);
impl PlanClose {
    pub fn close(self) -> Result<()> {
        let reply = broker::Client::call(&mut *self.0.borrow_mut(), Operation::Close)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            matches!(reply.value, Some(Data::Closed)),
            "Plan broker close reply changed"
        );
        Ok(())
    }
}
struct ServerSettings<'a> {
    cleanup_plan: &'a str,
    deadline: Duration,
    fault: Option<Probe>,
    plan_fault: emumee_core::plan_runtime::Fault,
    binding: Option<Value>,
    target_read_denied: Option<bool>,
    persona_read_denied: Option<bool>,
}
fn serve(
    root: &Path,
    containment: Value,
    mut service: Service,
    settings: ServerSettings<'_>,
) -> Result<()> {
    let ServerSettings {
        cleanup_plan,
        deadline,
        fault,
        plan_fault,
        binding,
        target_read_denied,
        persona_read_denied,
    } = settings;
    let ipc = root.join("ipc");
    let private = root.join("private");
    let mut requests = open_pinned(&ipc.join("requests.bin"), &ipc, false)?;
    let mut replies = open_pinned(&ipc.join("responses.bin"), &ipc, true)?;
    let mut journal = open_pinned_journal(&private.join("network-broker.journal"), &private)?;
    let mut count = 0;
    let mut bytes = 0;
    record(
        &mut journal,
        binding.unwrap_or_else(|| json!({"event":"broker_started","mode":"offline_replay"})),
        &mut count,
        &mut bytes,
    )?;
    let cleanup_plan_denied = File::open(cleanup_plan).is_err();
    ensure!(
        cleanup_plan_denied,
        "Contained broker can read the controller cleanup plan"
    );
    let mut ready = serde_json::to_value(&containment)?;
    ready["cleanup_plan_read_denied"] = cleanup_plan_denied.into();
    if let Some(denied) = target_read_denied {
        ready["target_read_denied"] = denied.into();
    }
    if let Some(denied) = persona_read_denied {
        ready["persona_read_denied"] = denied.into();
    }
    super::save_new(
        &root.join("broker/broker-ready.json"),
        &serde_json::to_vec_pretty(&ready)?,
    )?;
    let mut reader = FrameReader::default();
    let started = Instant::now();
    while !service.closed() {
        ensure!(started.elapsed() < deadline, "Offline broker timed out");
        if let Some(packet) = reader.poll(&mut requests).map_err(anyhow::Error::msg)? {
            let request: Request = serde_json::from_slice(&packet)?;
            let reply = service
                .handle(request, |event| {
                    let attempt = matches!(
                        event["event"].as_str(),
                        Some("http_request_attempt" | "dns_attempt")
                    );
                    record(&mut journal, event, &mut count, &mut bytes)
                        .map_err(|e| format!("{e:#}"))?;
                    if attempt {
                        match if plan_fault == emumee_core::plan_runtime::Fault::BrokerDeath {
                            Probe::Crash
                        } else if plan_fault == emumee_core::plan_runtime::Fault::BrokerPartial {
                            Probe::Partial
                        } else {
                            fault.unwrap_or(Probe::Normal)
                        } {
                            Probe::Crash => std::process::exit(23),
                            Probe::Partial => {
                                journal
                                    .write_all(b"{\"event\":\"unfinished")
                                    .map_err(|e| e.to_string())?;
                                journal.sync_data().map_err(|e| e.to_string())?;
                                std::process::exit(24)
                            }
                            Probe::Hang => std::thread::sleep(Duration::from_secs(20)),
                            _ => (),
                        }
                    }
                    Ok(())
                })
                .map_err(anyhow::Error::msg)?;
            write_selected_packet(
                &mut replies,
                &reply,
                if fault.is_none() {
                    StreamPolicy::Closed128
                } else {
                    StreamPolicy::Fixture
                },
            )?;
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    Ok(())
}
fn call(
    output: &mut File,
    input: &mut File,
    reader: &mut FrameReader,
    request: Request,
) -> Result<Reply> {
    call_selected(output, input, reader, request, StreamPolicy::Fixture)
}
fn call_selected(
    output: &mut File,
    input: &mut File,
    reader: &mut FrameReader,
    request: Request,
    policy: StreamPolicy,
) -> Result<Reply> {
    let id = request.id;
    write_selected_packet(output, &request, policy)?;
    let started = Instant::now();
    loop {
        if let Some(packet) = reader.poll(input).map_err(anyhow::Error::msg)? {
            let reply: Reply = serde_json::from_slice(&packet)?;
            reply.validate(id).map_err(anyhow::Error::msg)?;
            return Ok(reply);
        }
        ensure!(
            started.elapsed() < Duration::from_secs(3),
            "Broker reply timed out"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
pub fn client(root: &Path, expected: &str) -> Result<()> {
    let containment = prepare_worker()?;
    let config = config(root, expected)?;
    let ipc = root.join("ipc");
    let private_denied = File::open(root.join("private/network-broker.journal")).is_err();
    let fixture_denied = File::open(root.join("private/http-fixtures.json"))
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(5));
    let cleanup_plan_denied = File::open(&config.cleanup_plan).is_err();
    let overwrite_denied = std::fs::OpenOptions::new()
        .write(true)
        .open(ipc.join("requests.bin"))
        .is_err();
    let reply_append_denied = std::fs::OpenOptions::new()
        .append(true)
        .open(ipc.join("responses.bin"))
        .is_err();
    let create_denied = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(ipc.join("injected.bin"))
        .is_err();
    ensure!(
        private_denied
            && fixture_denied
            && cleanup_plan_denied
            && overwrite_denied
            && reply_append_denied
            && create_denied,
        "Broker IPC/journal permissions are too broad"
    );
    super::save_new(
        &root.join("worker/client-ready.json"),
        &serde_json::to_vec_pretty(
            &json!({"containment":containment,"private_journal_denied":private_denied,"private_fixtures_denied":fixture_denied,"cleanup_plan_read_denied":cleanup_plan_denied,"request_overwrite_denied":overwrite_denied,"response_append_denied":reply_append_denied,"ipc_creation_denied":create_denied}),
        )?,
    )?;
    if matches!(config.probe, Probe::WorkerCrash) {
        std::process::exit(25);
    }
    if matches!(
        config.probe,
        Probe::ControllerCrash | Probe::ControllerPartial
    ) {
        std::thread::sleep(Duration::from_secs(20));
        anyhow::bail!("Controller crash fixture was not terminated by its job");
    }
    let mut requests = open_pinned(&ipc.join("requests.bin"), &ipc, true)?;
    let mut replies = open_pinned(&ipc.join("responses.bin"), &ipc, false)?;
    let mut reader = FrameReader::default();
    if matches!(config.probe, Probe::BadFrame) {
        requests.write_all(&u32::MAX.to_le_bytes())?;
        std::thread::sleep(Duration::from_secs(10));
        anyhow::bail!("Bad frame was not rejected");
    }
    if matches!(config.probe, Probe::BadId) {
        broker::write_packet(
            &mut requests,
            &Request {
                id: 2,
                request: Operation::Ping,
            },
        )
        .map_err(anyhow::Error::msg)?;
        std::thread::sleep(Duration::from_secs(10));
        anyhow::bail!("Bad sequence was not rejected");
    }
    let ping = call(
        &mut requests,
        &mut replies,
        &mut reader,
        Request {
            id: 1,
            request: Operation::Ping,
        },
    )?;
    ensure!(matches!(ping.value, Some(Data::Pong)), "Broker ping failed");
    if config.probe.native().is_some()
        || config.probe.winhttp().is_some()
        || config.probe.internet().is_some()
    {
        let architecture = match config.architecture.as_str() {
            "x64" => emumee_core::pe::Architecture::X64,
            "x86" => emumee_core::pe::Architecture::X86,
            _ => anyhow::bail!("Invalid native broker fixture architecture"),
        };
        let rpc = Rc::new(RefCell::new(Rpc {
            requests,
            replies,
            reader,
            next: 2,
            stream_policy: StreamPolicy::Fixture,
        }));
        let budget = if matches!(
            config.probe,
            Probe::NativePartial | Probe::NativeBinaryPartial
        ) {
            if architecture == emumee_core::pe::Architecture::X64 {
                10
            } else {
                7
            }
        } else {
            1000
        };
        let client = Box::new(SharedRpc(Rc::clone(&rpc)));
        let execution = if let Some(fixture) = config.probe.internet() {
            emumee_engine::run_internet_fixture(architecture, fixture, budget, client)?
        } else if let Some(fixture) = config.probe.winhttp() {
            emumee_engine::run_winhttp_fixture(architecture, fixture, budget, client)?
        } else {
            emumee_engine::run_download_fixture(
                architecture,
                config.probe.native().unwrap(),
                budget,
                client,
            )?
        };
        super::save_artifacts(&root.join("worker"), &execution.artifacts)?;
        let closed = broker::Client::call(&mut *rpc.borrow_mut(), Operation::Close)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            matches!(closed.value, Some(Data::Closed)),
            "Broker close acknowledgement missing"
        );
        super::save_new(
            &root.join("worker/broker-result.json"),
            &serde_json::to_vec_pretty(
                &json!({"schema":1,"request_sha256":expected,"containment":containment,"execution":execution,"scope":"Generated native networking fixture uses contained offline broker and guest-only response/file capture; not general sample execution."}),
            )?,
        )?;
        return Ok(());
    }
    let full_response = config
        .probe
        .http()
        .then(|| emumee_core::fixtures::http::response(config.probe));
    let operation = if full_response.is_some() {
        let mut request = emumee_core::fixtures::http::request(config.probe);
        match config.probe {
            Probe::HttpHeaders => {
                let value = request.headers.remove("x-case").unwrap();
                request.headers.insert("X-CASE".into(), value);
            }
            Probe::HttpBodyMiss => request.body.push(0),
            Probe::HttpChunkedMiss => request.chunked = false,
            _ => (),
        }
        Operation::Http { request }
    } else {
        match config.probe {
            Probe::Dns => Operation::Resolve {
                host: "example.invalid".into(),
            },
            Probe::Miss => Operation::HttpGet {
                url: format!("{}?unmatched", config.fixture.url),
            },
            _ => Operation::HttpGet {
                url: config.fixture.url,
            },
        }
    };
    let reply = call(
        &mut requests,
        &mut replies,
        &mut reader,
        Request {
            id: 2,
            request: operation,
        },
    )?;
    if matches!(
        config.probe,
        Probe::Miss | Probe::Dns | Probe::HttpBodyMiss | Probe::HttpChunkedMiss
    ) {
        ensure!(!reply.ok, "Offline request unexpectedly succeeded");
    } else if let Some(expected_response) = &full_response {
        ensure!(
            matches!(&reply.value,Some(Data::HttpFull{response}) if response==expected_response),
            "Full binary HTTP fixture reply changed"
        );
    } else {
        ensure!(
            matches!(&reply.value,Some(Data::Http{status,body}) if *status==config.fixture.status && body==&config.fixture.body),
            "Offline fixture reply changed"
        );
    }
    let closed = call(
        &mut requests,
        &mut replies,
        &mut reader,
        Request {
            id: 3,
            request: Operation::Close,
        },
    )?;
    ensure!(
        matches!(closed.value, Some(Data::Closed)),
        "Broker close acknowledgement missing"
    );
    super::save_new(
        &root.join("worker/broker-result.json"),
        &serde_json::to_vec_pretty(
            &json!({"schema":1,"request_sha256":expected,"containment":containment,"reply":reply,"scope":"Fixed broker boundary fixture; no general guest API integration or external network."}),
        )?,
    )?;
    Ok(())
}

#[cfg(test)]
mod plan_stream_tests {
    use super::*;
    #[test]
    fn whole_frame_caps_reject_overflow_and_never_reserve_a_partial_header() {
        assert_eq!(
            checked_packet_end(broker::MAX_STREAM as u64 - 5, 1).unwrap(),
            broker::MAX_STREAM as u64
        );
        assert!(checked_packet_end(broker::MAX_STREAM as u64 - 4, 1).is_err());
        assert!(checked_packet_end(u64::MAX, 1).is_err());
        assert!(checked_packet_end(0, 0).is_err());
        assert!(checked_packet_end(0, broker::MAX_PACKET + 1).is_err());
        assert_eq!(
            checked_packet_end(0, broker::MAX_PACKET).unwrap(),
            broker::MAX_PACKET as u64 + 4
        );
    }
}
