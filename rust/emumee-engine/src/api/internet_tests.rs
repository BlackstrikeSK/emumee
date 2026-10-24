use crate::*;
use emumee_core::{
    broker::{Client, Data, Operation, Reply},
    fixtures::InternetFixture as F,
    networkfixtures::HttpResponse,
};
use std::{cell::Cell, rc::Rc};
struct Fake {
    calls: Rc<Cell<usize>>,
    empty: bool,
    post: bool,
    empty_post: bool,
}
impl Client for Fake {
    fn call(&mut self, operation: Operation) -> std::result::Result<Reply, String> {
        self.calls.set(self.calls.get() + 1);
        let Operation::Http { request } = operation else {
            panic!("unexpected operation")
        };
        assert_eq!(request.method, if self.post { "POST" } else { "GET" });
        assert_eq!(
            request.body,
            if self.post && !self.empty_post {
                b"RUSTBODY".to_vec()
            } else {
                vec![]
            }
        );
        assert!(!request.chunked);
        assert_eq!(
            request.headers,
            if self.post && !self.empty_post {
                std::collections::BTreeMap::from([("x-case".into(), "Exact".into())])
            } else {
                Default::default()
            }
        );
        if request.url.ends_with("/absent") {
            return Ok(Reply {
                id: 1,
                ok: false,
                value: None,
                error: Some("offline fixture miss".into()),
            });
        }
        assert_eq!(
            request.url,
            if self.post {
                "https://fixture.invalid:443/payload"
            } else {
                "https://fixture.invalid/payload"
            }
        );
        Ok(Reply {
            id: 1,
            ok: true,
            error: None,
            value: Some(Data::HttpFull {
                response: HttpResponse {
                    status: 200,
                    reason: "OK".into(),
                    version: "HTTP/1.0".into(),
                    headers: vec![
                        ("Set-Cookie".into(), "one".into()),
                        ("Set-Cookie".into(), "two".into()),
                    ],
                    body: if self.empty {
                        vec![]
                    } else {
                        (0..65536).map(|i| i as u8).collect()
                    },
                },
            }),
        })
    }
}
fn fake(empty: bool) -> (Box<dyn Client>, Rc<Cell<usize>>) {
    let calls = Rc::new(Cell::new(0));
    (
        Box::new(Fake {
            calls: Rc::clone(&calls),
            empty,
            post: false,
            empty_post: false,
        }),
        calls,
    )
}
#[test]
fn wininet_owned_ansi_unicode_binary_eof_failure_and_handle_lifecycles() {
    for arch in [Architecture::X86, Architecture::X64] {
        for fixture in [
            F::Ansi,
            F::Wide,
            F::Split,
            F::Empty,
            F::Miss,
            F::Closed,
            F::BadRead,
            F::BadCount,
            F::NullAvailable,
        ] {
            let (client, calls) = fake(matches!(fixture, F::Empty));
            let result = run_internet_fixture(arch, fixture, 1000, client).unwrap();
            assert_eq!(result.error, None, "{arch:?} {fixture:?}");
            assert_eq!(
                result.guest_entry_return,
                Some(if matches!(fixture, F::Miss) { 0 } else { 1 })
            );
            assert_eq!(calls.get(), 1);
            assert_eq!(result.network.calls, 1);
            assert_eq!(
                result.artifacts.len(),
                usize::from(!matches!(fixture, F::Empty | F::Miss))
            );
            if let Some(a) = result.artifacts.first() {
                assert_eq!(a.data, (0..65536).map(|i| i as u8).collect::<Vec<_>>());
                assert_eq!(a.observations[0].source, "wininet_response");
            }
        }
        for fixture in [F::Async, F::Flags] {
            let (client, calls) = fake(false);
            let result = run_internet_fixture(arch, fixture, 1000, client).unwrap();
            assert_eq!(calls.get(), 0);
            assert_eq!(result.completion_reason, "error");
            assert!(result.artifacts.is_empty());
        }
        let result = run_generated_image(
            &emumee_core::fixtures::internet_probe(arch, F::Wide),
            1000,
            30_000_000,
        )
        .unwrap();
        assert!(result.error.unwrap().contains("host fallback is disabled"));
        assert!(result.artifacts.is_empty());
    }
}
#[test]
fn wininet_every_budget_prefix_captures_only_the_completed_broker_reply() {
    for arch in [Architecture::X86, Architecture::X64] {
        let (client, _) = fake(false);
        let full = run_internet_fixture(arch, F::Split, 1000, client).unwrap();
        assert_eq!(full.guest_entry_return, Some(1));
        for budget in 1..full.instruction_count {
            let (client, calls) = fake(false);
            let part = run_internet_fixture(arch, F::Split, budget, client).unwrap();
            assert_eq!(
                part.completion_reason, "instruction_budget",
                "{arch:?} {budget}: {:?}",
                part.error
            );
            assert_eq!(part.guest_entry_return, None);
            assert_eq!(part.artifacts.len(), calls.get());
        }
    }
}

#[test]
fn wininet_headers_and_direct_posts_preserve_abi_bytes_indexes_and_retry_state() {
    for arch in [Architecture::X86, Architecture::X64] {
        for fixture in [
            F::PostA,
            F::PostW,
            F::SendWideLength,
            F::SendBeforeRead,
            F::QueryA,
            F::QueryW,
            F::QuerySmallA,
            F::QuerySmallW,
            F::QueryCustomA,
            F::QueryCustomW,
            F::QueryNull,
            F::QueryReadOnly,
            F::QueryMissing,
        ] {
            let calls = Rc::new(Cell::new(0));
            let client = Box::new(Fake {
                calls: Rc::clone(&calls),
                empty: false,
                post: fixture.send(),
                empty_post: false,
            });
            let result = run_internet_fixture(arch, fixture, 1000, client).unwrap();
            assert_eq!(result.error, None, "{arch:?} {fixture:?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert_eq!(calls.get(), 1);
            assert_eq!(result.artifacts.len(), if fixture.send() { 2 } else { 1 });
            if fixture.send() {
                assert!(
                    result.artifacts.iter().any(|a| a.data == b"RUSTBODY"
                        && a.observations[0].source == "wininet_request_body")
                );
            }
            if matches!(fixture, F::SendWideLength | F::SendBeforeRead) {
                let error = if matches!(fixture, F::SendWideLength) {
                    87
                } else {
                    12019
                };
                assert!(
                    result
                        .api_events
                        .iter()
                        .any(|e| e.api.contains("HttpSendRequest")
                            && e.result == Some(0)
                            && e.last_error == error)
                );
            }
        }
    }
}

#[test]
fn direct_post_budget_prefixes_preserve_actual_request_and_response_capture_timing() {
    for arch in [Architecture::X86, Architecture::X64] {
        let make = || {
            let calls = Rc::new(Cell::new(0));
            (
                Box::new(Fake {
                    calls: Rc::clone(&calls),
                    empty: false,
                    post: true,
                    empty_post: false,
                }) as Box<dyn Client>,
                calls,
            )
        };
        let (client, _) = make();
        let full = run_internet_fixture(arch, F::PostW, 1000, client).unwrap();
        assert_eq!(full.guest_entry_return, Some(1));
        for budget in 1..full.instruction_count {
            let (client, calls) = make();
            let part = run_internet_fixture(arch, F::PostW, budget, client).unwrap();
            assert_eq!(part.error, None);
            assert_eq!(part.guest_entry_return, None);
            assert_eq!(part.artifacts.len(), calls.get() * 2);
        }
    }
}

#[test]
fn wininet_streamed_uploads_preserve_actual_head_bytes_zero_counts_and_deferred_end() {
    for arch in [Architecture::X86, Architecture::X64] {
        for fixture in [
            F::StreamA,
            F::StreamW,
            F::StreamZero,
            F::StreamLinked,
            F::StreamFull,
            F::StreamEmpty,
            F::StreamBadCount,
            F::StreamExcess,
            F::StreamBadStruct,
            F::StreamIncomplete,
            F::StreamClosed,
        ] {
            let calls = Rc::new(Cell::new(0));
            let client = Box::new(Fake {
                calls: Rc::clone(&calls),
                empty: false,
                post: true,
                empty_post: fixture.empty_post(),
            });
            let result = run_internet_fixture(arch, fixture, 1000, client).unwrap();
            let no_request = matches!(
                fixture,
                F::StreamBadStruct | F::StreamIncomplete | F::StreamClosed
            );
            assert_eq!(
                calls.get(),
                usize::from(!no_request),
                "{arch:?} {fixture:?}"
            );
            assert_eq!(
                result.artifacts.len(),
                if no_request {
                    0
                } else if fixture.empty_post() {
                    1
                } else {
                    2
                }
            );
            if matches!(fixture, F::StreamIncomplete) {
                assert!(result.error.unwrap().contains("incomplete end"));
                assert_eq!(result.guest_entry_return, None);
            } else {
                assert_eq!(result.error, None, "{arch:?} {fixture:?}");
                assert_eq!(result.guest_entry_return, Some(1));
            }
            if !matches!(fixture, F::StreamBadStruct) {
                assert_eq!(
                    result.network.uploads[0].bytes,
                    if fixture.empty_post() {
                        0
                    } else if matches!(fixture, F::StreamFull) {
                        8
                    } else {
                        4
                    }
                );
            }
            if matches!(fixture, F::StreamZero) {
                assert!(
                    result
                        .api_events
                        .iter()
                        .any(|e| e.api.ends_with("InternetWriteFile")
                            && e.result == Some(0)
                            && e.last_error == 87)
                );
            }
            if matches!(fixture, F::StreamLinked) {
                assert_eq!(result.network.uploads[0].phase, "staged_head_only");
            }
        }
    }
}

#[test]
fn wininet_streaming_every_budget_prefix_publishes_only_at_end_including_full_and_empty_initial_bodies()
 {
    for arch in [Architecture::X86, Architecture::X64] {
        for fixture in [F::StreamW, F::StreamFull, F::StreamEmpty] {
            let make = || {
                let calls = Rc::new(Cell::new(0));
                (
                    Box::new(Fake {
                        calls: Rc::clone(&calls),
                        empty: false,
                        post: true,
                        empty_post: fixture.empty_post(),
                    }) as Box<dyn Client>,
                    calls,
                )
            };
            let (client, _) = make();
            let full = run_internet_fixture(arch, fixture, 1000, client).unwrap();
            assert_eq!(
                full.guest_entry_return,
                Some(1),
                "{arch:?} {fixture:?}: {:?}",
                full.error
            );
            for budget in 1..full.instruction_count {
                let (client, calls) = make();
                let part = run_internet_fixture(arch, fixture, budget, client).unwrap();
                assert_eq!(part.error, None, "{arch:?} {fixture:?} {budget}");
                assert_eq!(part.guest_entry_return, None);
                assert_eq!(
                    part.artifacts.len(),
                    calls.get() * if fixture.empty_post() { 1 } else { 2 }
                );
            }
        }
    }
}
