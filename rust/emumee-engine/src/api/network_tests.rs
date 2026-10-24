use crate::*;
use emumee_core::{
    broker::{Client, Data, Operation, Reply},
    fixtures::{DownloadFixture as F, download_probe},
};
use std::{cell::Cell, rc::Rc};
struct Fake {
    reply: Result<Reply, String>,
    calls: Rc<Cell<usize>>,
}
impl Client for Fake {
    fn call(&mut self, operation: Operation) -> Result<Reply, String> {
        assert!(matches!(operation, Operation::HttpGet { .. }));
        self.calls.set(self.calls.get() + 1);
        self.reply.clone()
    }
}
fn client(reply: Result<Reply, String>) -> (Box<dyn Client>, Rc<Cell<usize>>) {
    let calls = Rc::new(Cell::new(0));
    (
        Box::new(Fake {
            reply,
            calls: Rc::clone(&calls),
        }),
        calls,
    )
}
fn good() -> Result<Reply, String> {
    Ok(Reply {
        id: 1,
        ok: true,
        value: Some(Data::Http {
            status: 200,
            body: b"RUST".to_vec(),
        }),
        error: None,
    })
}
#[test]
fn native_urlmon_ansi_wide_use_broker_and_capture_guest_files_in_both_abis() {
    for arch in [Architecture::X86, Architecture::X64] {
        for fixture in [F::Ansi, F::Wide] {
            let (client, calls) = client(good());
            let result = run_download_fixture(arch, fixture, 1000, client).unwrap();
            assert_eq!(result.guest_entry_return, Some(0), "{:?}", result.error);
            assert_eq!(result.completion_reason, "entry_return");
            assert_eq!(result.api_calls, 1);
            assert_eq!(calls.get(), 1);
            assert_eq!(result.artifacts.len(), 1);
            assert_eq!(result.artifacts[0].data, b"RUST");
            assert_eq!(result.artifacts[0].observations.len(), 2);
            assert_eq!(
                result.artifacts[0].observations[0].source,
                "urlmon_download"
            );
            assert_eq!(
                result.artifacts[0].observations[0].guest_path,
                "c:\\workspace\\payload.bin"
            );
            assert_eq!(result.network.calls, 1);
            assert_eq!(result.network.events[0].status, Some(200));
        }
    }
}
#[test]
fn full_binary_urlmon_preserves_bytes_empty_creation_and_partial_captures() {
    for arch in [Architecture::X86, Architecture::X64] {
        for fixture in [F::Ansi, F::Wide] {
            for size in [0, 65536] {
                let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
                let (client, _) = client(Ok(Reply {
                    id: 1,
                    ok: true,
                    value: Some(Data::HttpFull {
                        response: emumee_core::networkfixtures::HttpResponse {
                            status: 200,
                            reason: "OK".into(),
                            version: "HTTP/1.1".into(),
                            headers: Vec::new(),
                            body: data.clone(),
                        },
                    }),
                    error: None,
                }));
                let result = run_download_fixture(arch, fixture, 1000, client).unwrap();
                assert_eq!(result.guest_entry_return, Some(0));
                assert_eq!(result.network.events[0].bytes, size);
                assert!(result.network.events[0].destination_created);
                assert_eq!(result.artifacts.len(), usize::from(size > 0));
                if size > 0 {
                    assert_eq!(result.artifacts[0].data, data);
                }
            }
        }
        let (client, _) = client(Ok(Reply {
            id: 1,
            ok: true,
            value: Some(Data::HttpFull {
                response: emumee_core::fixtures::http::response(
                    emumee_core::broker::Probe::NativeBinaryA,
                ),
            }),
            error: None,
        }));
        let result = run_download_fixture(
            arch,
            F::Ansi,
            if arch == Architecture::X64 { 10 } else { 7 },
            client,
        )
        .unwrap();
        assert_eq!(result.completion_reason, "instruction_budget");
        assert_eq!(result.guest_entry_return, None);
        assert_eq!(result.artifacts[0].data.len(), 65536);
        assert_eq!(result.artifacts[0].observations.len(), 2);
    }
}
#[test]
fn every_native_urlmon_budget_prefix_preserves_only_executed_transfers() {
    for arch in [Architecture::X86, Architecture::X64] {
        let full = if arch == Architecture::X64 { 11 } else { 8 };
        for budget in 1..=full {
            let (client, calls) = client(good());
            let result = run_download_fixture(arch, F::Ansi, budget, client).unwrap();
            assert_eq!(result.instruction_count, budget);
            assert_eq!(result.error, None);
            assert_eq!(
                result.guest_entry_return,
                if budget == full { Some(0) } else { None }
            );
            assert_eq!(result.artifacts.len(), calls.get());
            assert_eq!(result.network.calls, calls.get() as u64);
            let transfer_at = if arch == Architecture::X64 {
                full - 2
            } else {
                full - 1
            };
            assert_eq!(calls.get(), usize::from(budget >= transfer_at));
        }
    }
}
#[test]
fn urlmon_denial_null_callback_and_destination_cancellation_do_not_invent_files() {
    for arch in [Architecture::X86, Architecture::X64] {
        let (denied, _) = client(Ok(Reply {
            id: 1,
            ok: false,
            value: None,
            error: Some("offline denied".into()),
        }));
        let result = run_download_fixture(arch, F::Miss, 1000, denied).unwrap();
        assert_eq!(result.guest_entry_return, Some(0x800c0008));
        assert!(result.artifacts.is_empty());
        assert!(
            result.network.events[0]
                .error
                .as_ref()
                .unwrap()
                .contains("denied")
        );
        for fixture in [F::Callback, F::NullUrl] {
            let (client, calls) = client(good());
            let result = run_download_fixture(arch, fixture, 1000, client).unwrap();
            assert_eq!(result.completion_reason, "error");
            assert_eq!(result.guest_entry_return, None);
            assert!(result.artifacts.is_empty());
            assert_eq!(calls.get(), 0);
        }
        let (client, calls) = client(good());
        let result = run_download_fixture(arch, F::MissingParent, 1000, client).unwrap();
        assert_eq!(result.guest_entry_return, Some(0));
        assert!(result.artifacts.is_empty());
        assert_eq!(calls.get(), 1);
        assert!(
            result.network.events[0]
                .error
                .as_ref()
                .unwrap()
                .contains("cancelled")
        );
    }
}
#[test]
fn native_urlmon_has_no_host_fallback_or_guessed_unsupported_broker_result() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = run_generated_image(&download_probe(arch, F::Ansi), 1000, 1_000_000).unwrap();
        assert!(result.error.unwrap().contains("host fallback is disabled"));
        assert!(result.artifacts.is_empty());
        for reply in [
            Err("transport disconnected".into()),
            Ok(Reply {
                id: 1,
                ok: true,
                value: Some(Data::Pong),
                error: None,
            }),
            Ok(Reply {
                id: 1,
                ok: true,
                value: Some(Data::Http {
                    status: 404,
                    body: vec![],
                }),
                error: None,
            }),
            Ok(Reply {
                id: 1,
                ok: true,
                value: Some(Data::Http {
                    status: 200,
                    body: vec![0; 4097],
                }),
                error: None,
            }),
        ] {
            let (client, _) = client(reply);
            let result = run_download_fixture(arch, F::Ansi, 1000, client).unwrap();
            assert_eq!(result.completion_reason, "error");
            assert_eq!(result.guest_entry_return, None);
            assert!(result.artifacts.is_empty());
        }
    }
}
