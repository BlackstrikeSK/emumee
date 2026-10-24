use crate::*;
use emumee_core::{
    broker::{Client, Data, Operation, Reply},
    fixtures::{WinHttpFixture as F, winhttp_probe},
    networkfixtures::HttpResponse,
};
use std::{cell::Cell, rc::Rc};
struct Fake {
    denied: bool,
    empty: bool,
    upload: bool,
    chunked: bool,
    calls: Rc<Cell<usize>>,
}
fn chunk_fake() -> (Box<dyn Client>, Rc<Cell<usize>>) {
    let calls = Rc::new(Cell::new(0));
    (
        Box::new(Fake {
            denied: false,
            empty: false,
            upload: true,
            chunked: true,
            calls: Rc::clone(&calls),
        }),
        calls,
    )
}
#[test]
fn native_chunk_wire_split_and_zero_write_match_owned_windows_reference() {
    for arch in [Architecture::X86, Architecture::X64] {
        for fixture in [F::Chunked, F::ChunkedSplit, F::ChunkedZero] {
            let (client, calls) = chunk_fake();
            let result = run_winhttp_fixture(arch, fixture, 1000, client).unwrap();
            assert_eq!(result.error, None, "{fixture:?}");
            assert_eq!(result.guest_entry_return, Some(0x03020100));
            assert_eq!(calls.get(), 1);
            assert_eq!(result.artifacts.len(), 2);
            assert!(result.artifacts.iter().any(|a| a.data == b"RUSTBODY"));
            assert_eq!(result.network.uploads[0].total, None);
            assert_eq!(result.network.uploads.last().unwrap().bytes, 8);
            if matches!(fixture, F::ChunkedZero) {
                assert!(result.api_events.iter().any(
                    |event| event.api.ends_with("WinHttpWriteData")
                        && event.result == Some(0)
                        && event.last_error == 87
                ));
            }
        }
        for fixture in [F::ChunkedIncomplete, F::ChunkedMalformed] {
            let (client, calls) = chunk_fake();
            let result = run_winhttp_fixture(arch, fixture, 1000, client).unwrap();
            assert_eq!(calls.get(), 0);
            assert!(result.artifacts.is_empty());
            assert_eq!(result.network.calls, 0);
            if matches!(fixture, F::ChunkedIncomplete) {
                assert_eq!(result.error, None);
                assert_eq!(result.guest_entry_return, Some(0));
            } else {
                assert_eq!(result.completion_reason, "error");
                assert!(result.error.unwrap().contains("malformed chunk size"));
            }
        }
    }
}
#[test]
fn chunk_wire_budget_prefixes_never_publish_before_terminator() {
    for arch in [Architecture::X86, Architecture::X64] {
        let (client, _) = chunk_fake();
        let full = run_winhttp_fixture(arch, F::Chunked, 1000, client).unwrap();
        assert_eq!(full.error, None);
        for budget in 1..=full.instruction_count {
            let (client, calls) = chunk_fake();
            let result = run_winhttp_fixture(arch, F::Chunked, budget, client).unwrap();
            assert_eq!(result.error, None);
            assert_eq!(result.instruction_count, budget);
            assert_eq!(result.artifacts.len(), calls.get() * 2);
            assert_eq!(
                result.guest_entry_return,
                if budget == full.instruction_count {
                    Some(0x03020100)
                } else {
                    None
                }
            );
        }
    }
}
impl Client for Fake {
    fn call(&mut self, operation: Operation) -> std::result::Result<Reply, String> {
        let Operation::Http { request } = operation else {
            panic!("Unexpected WinHTTP broker operation")
        };
        assert_eq!(request.method, if self.upload { "POST" } else { "GET" });
        assert!(
            request
                .url
                .starts_with("https://fixture.invalid:443/payload")
        );
        if self.chunked {
            assert_eq!(request.headers.len(), 1);
            assert_eq!(request.headers["transfer-encoding"], "chunked");
        } else {
            assert!(request.headers.is_empty());
        }
        if self.upload {
            assert_eq!(request.body, b"RUSTBODY");
        } else {
            assert!(request.body.is_empty());
        }
        assert_eq!(request.chunked, self.chunked);
        self.calls.set(self.calls.get() + 1);
        Ok(Reply {
            id: 1,
            ok: !self.denied,
            value: (!self.denied).then(|| Data::HttpFull {
                response: HttpResponse {
                    status: 200,
                    reason: "OK".into(),
                    version: "HTTP/1.1".into(),
                    headers: vec![
                        ("Set-Cookie".into(), "one".into()),
                        ("Set-Cookie".into(), "two".into()),
                    ],
                    body: if self.empty {
                        Vec::new()
                    } else {
                        (0..32).collect()
                    },
                },
            }),
            error: self.denied.then(|| "offline denied".into()),
        })
    }
}
fn fake(denied: bool) -> (Box<dyn Client>, Rc<Cell<usize>>) {
    let calls = Rc::new(Cell::new(0));
    (
        Box::new(Fake {
            denied,
            empty: false,
            upload: false,
            chunked: false,
            calls: Rc::clone(&calls),
        }),
        calls,
    )
}
fn upload_fake() -> (Box<dyn Client>, Rc<Cell<usize>>) {
    let calls = Rc::new(Cell::new(0));
    (
        Box::new(Fake {
            denied: false,
            empty: false,
            upload: true,
            chunked: false,
            calls: Rc::clone(&calls),
        }),
        calls,
    )
}
#[test]
fn native_staged_uploads_preserve_exact_body_and_failed_writes_do_not_append() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (fixture, error) in [
            (F::Upload, None),
            (F::UploadEarly, Some(12019)),
            (F::UploadBadCount, Some(998)),
            (F::UploadOverrun, Some(87)),
        ] {
            let (client, calls) = upload_fake();
            let result = run_winhttp_fixture(arch, fixture, 1000, client).unwrap();
            assert_eq!(result.error, None, "{fixture:?}");
            assert_eq!(result.guest_entry_return, Some(0x03020100));
            assert_eq!(calls.get(), 1);
            assert_eq!(result.network.uploads[0].bytes, 4);
            assert_eq!(result.network.uploads[0].total, Some(8));
            assert_eq!(result.network.uploads.last().unwrap().bytes, 8);
            assert_eq!(result.network.events[0].api, "WinHttpReceiveResponse");
            assert_eq!(result.artifacts.len(), 2);
            assert!(result.artifacts.iter().any(
                |a| a.data == b"RUSTBODY" && a.observations[0].source == "winhttp_request_body"
            ));
            if let Some(code) = error {
                assert!(
                    result
                        .api_events
                        .iter()
                        .any(|event| event.result == Some(0) && event.last_error == code)
                );
            }
        }
        for (fixture, code) in [(F::UploadIncomplete, 12019), (F::UploadClosed, 6)] {
            let (client, calls) = upload_fake();
            let result = run_winhttp_fixture(arch, fixture, 1000, client).unwrap();
            assert_eq!(result.error, None);
            assert_eq!(result.guest_entry_return, Some(0));
            assert_eq!(calls.get(), 0);
            assert!(result.artifacts.is_empty());
            assert_eq!(result.network.calls, 0);
            assert!(
                result
                    .api_events
                    .iter()
                    .any(|event| event.result == Some(0) && event.last_error == code)
            );
        }
    }
}
#[test]
fn staged_upload_budget_prefixes_never_publish_incomplete_bodies() {
    for arch in [Architecture::X86, Architecture::X64] {
        let (client, _) = upload_fake();
        let full = run_winhttp_fixture(arch, F::Upload, 1000, client).unwrap();
        assert_eq!(full.error, None);
        for budget in 1..=full.instruction_count {
            let (client, calls) = upload_fake();
            let result = run_winhttp_fixture(arch, F::Upload, budget, client).unwrap();
            assert_eq!(result.error, None);
            assert_eq!(result.instruction_count, budget);
            assert_eq!(result.artifacts.len(), calls.get() * 2);
            assert_eq!(
                result.guest_entry_return,
                if budget == full.instruction_count {
                    Some(0x03020100)
                } else {
                    None
                }
            );
        }
    }
}
#[test]
fn native_winhttp_header_queries_size_buffers_enumerate_duplicates_and_preserve_body() {
    for arch in [Architecture::X86, Architecture::X64] {
        for fixture in [F::QueryStatus, F::QuerySmall, F::QueryCustom, F::QueryRaw] {
            let (client, _) = fake(false);
            let result = run_winhttp_fixture(arch, fixture, 1000, client).unwrap();
            assert_eq!(result.error, None, "{fixture:?}");
            assert_eq!(result.guest_entry_return, Some(0x03020100));
            assert!(
                result
                    .api_events
                    .iter()
                    .any(|event| event.api.ends_with("WinHttpQueryHeaders")
                        && event.result == Some(1))
            );
            if matches!(fixture, F::QuerySmall | F::QueryCustom) {
                let code = if matches!(fixture, F::QuerySmall) {
                    122
                } else {
                    12150
                };
                assert!(result.api_events.iter().any(|event| {
                    event.api.ends_with("WinHttpQueryHeaders")
                        && event.result == Some(0)
                        && event.last_error == code
                }));
            }
        }
    }
}
#[test]
fn native_winhttp_empty_eof_zeros_count_and_leaves_buffer_untouched() {
    for arch in [Architecture::X86, Architecture::X64] {
        let client = Box::new(Fake {
            denied: false,
            empty: true,
            upload: false,
            chunked: false,
            calls: Rc::new(Cell::new(0)),
        });
        let result = run_winhttp_fixture(arch, F::Empty, 1000, client).unwrap();
        assert_eq!(result.error, None);
        assert_eq!(result.guest_entry_return, Some(0));
        assert!(result.artifacts.is_empty());
        assert_eq!(result.network.events[0].bytes, 0);
        assert!(
            result
                .api_events
                .iter()
                .any(|event| event.api.ends_with("WinHttpReadData") && event.result == Some(1))
        );
    }
}
#[test]
fn native_winhttp_returned_handles_and_binary_guest_reads_work_in_both_abis() {
    for arch in [Architecture::X86, Architecture::X64] {
        let (client, calls) = fake(false);
        let result = run_winhttp_fixture(arch, F::Normal, 1000, client).unwrap();
        assert_eq!(result.error, None);
        assert_eq!(result.guest_entry_return, Some(0x03020100));
        assert_eq!(calls.get(), 1);
        assert_eq!(result.network.calls, 1);
        assert_eq!(result.network.events[0].api, "WinHttpSendRequest");
        assert_eq!(result.artifacts.len(), 1);
        assert_eq!(result.artifacts[0].data, (0..32).collect::<Vec<_>>());
        assert_eq!(
            result.artifacts[0].observations[0].source,
            "winhttp_response"
        );
        assert_eq!(
            result.artifacts[0].observations[0].guest_path,
            "https://fixture.invalid:443/payload"
        );
    }
}
#[test]
fn native_winhttp_bad_outputs_and_readiness_do_not_consume_the_response() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (fixture, api, error) in [
            (F::BeforeReceive, "WinHttpReadData", 12019),
            (F::BadReadBuffer, "WinHttpReadData", 998),
            (F::BadAvailable, "WinHttpQueryDataAvailable", 998),
        ] {
            let (client, _) = fake(false);
            let result = run_winhttp_fixture(arch, fixture, 1000, client).unwrap();
            assert_eq!(result.error, None);
            assert_eq!(result.guest_entry_return, Some(0x03020100));
            assert!(
                result
                    .api_events
                    .iter()
                    .any(|event| event.api.ends_with(api)
                        && event.result == Some(0)
                        && event.last_error == error)
            );
        }
    }
}
#[test]
fn native_winhttp_close_denial_async_and_missing_broker_remain_explicit() {
    for arch in [Architecture::X86, Architecture::X64] {
        let (client, _) = fake(false);
        let result = run_winhttp_fixture(arch, F::CloseParent, 1000, client).unwrap();
        assert_eq!(result.error, None);
        assert_eq!(result.guest_entry_return, Some(0));
        assert!(
            result
                .api_events
                .iter()
                .any(|event| event.api.ends_with("WinHttpReadData")
                    && event.result == Some(0)
                    && event.last_error == 6)
        );
        let (client, calls) = fake(true);
        let result = run_winhttp_fixture(arch, F::Miss, 1000, client).unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(result.guest_entry_return, Some(0));
        assert!(result.artifacts.is_empty());
        assert_eq!(result.network.events[0].result, Some(0));
        assert!(
            result.network.events[0]
                .error
                .as_ref()
                .unwrap()
                .contains("denied")
        );
        let (client, calls) = fake(false);
        let result = run_winhttp_fixture(arch, F::Async, 1000, client).unwrap();
        assert_eq!(calls.get(), 0);
        assert_eq!(result.completion_reason, "error");
        assert!(result.error.unwrap().contains("asynchronous"));
        assert!(result.artifacts.is_empty());
        let result = run_generated_image(&winhttp_probe(arch, F::Normal), 1000, 1_000_000).unwrap();
        assert!(result.error.unwrap().contains("host fallback is disabled"));
        assert!(result.artifacts.is_empty());
    }
}
#[test]
fn every_winhttp_budget_prefix_preserves_only_executed_broker_response_evidence() {
    for arch in [Architecture::X86, Architecture::X64] {
        let (client, _) = fake(false);
        let full = run_winhttp_fixture(arch, F::Normal, 1000, client).unwrap();
        assert_eq!(full.error, None);
        for budget in 1..=full.instruction_count {
            let (client, calls) = fake(false);
            let result = run_winhttp_fixture(arch, F::Normal, budget, client).unwrap();
            assert_eq!(result.error, None);
            assert_eq!(result.instruction_count, budget);
            assert_eq!(result.artifacts.len(), calls.get());
            assert_eq!(
                result.guest_entry_return,
                if budget == full.instruction_count {
                    Some(0x03020100)
                } else {
                    None
                }
            );
        }
    }
}
