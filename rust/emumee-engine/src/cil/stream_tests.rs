use super::*;
fn objects(result: &Execution) -> usize {
    result
        .framework
        .streams
        .as_ref()
        .map(|s| s.objects)
        .unwrap_or(0)
}
fn bytes(result: &Execution, array: usize) -> Vec<i32> {
    result.arrays.evidence[array]
        .preview
        .iter()
        .map(|v| {
            if let Value::I32(n) = v {
                *n
            } else {
                panic!("not a byte")
            }
        })
        .collect()
}
#[test]
fn actual_newobj_cil_preserves_owned_borrowed_and_object_reference_behavior() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (case, expected, stream_count, array_count) in [
            (CilFixture::StreamOwned, 82, 1, 1),
            (CilFixture::StreamFile, 17, 1, 1),
            (CilFixture::StreamBorrowedWrite, 81, 1, 1),
            (CilFixture::StreamBorrowedRead, 81, 1, 1),
            (CilFixture::StreamCanWrite, 0, 1, 1),
            (CilFixture::StreamToArrayCopy, 65, 1, 2),
            (CilFixture::StreamClose, 3, 1, 2),
            (CilFixture::StreamSparse, 6, 1, 1),
            (CilFixture::StreamEmptyWrite, 0, 1, 1),
            (CilFixture::StreamShrink, 0, 1, 2),
            (CilFixture::StreamSeek, 67, 1, 1),
            (CilFixture::StreamRead, 66, 1, 2),
            (CilFixture::StreamCopy, 67, 2, 2),
            (CilFixture::StreamIdentity, 0, 2, 0),
            (CilFixture::StreamAlias, 1, 1, 0),
            (CilFixture::StreamObjectLocal, 82, 1, 1),
            (CilFixture::StreamBaseLocal, 82, 1, 1),
            (CilFixture::StreamObjectClassLocal, 82, 1, 1),
            (CilFixture::StreamObjectArray, 82, 1, 2),
            (CilFixture::StreamObjectArrayKinds, 65, 1, 2),
            (CilFixture::StreamStaticCall, 82, 1, 1),
        ] {
            let full = run_fixture(arch, case, 1, 1000).unwrap();
            assert_eq!(
                full.completion_reason, "entry_return",
                "{case:?}: {:?}",
                full.error
            );
            assert_eq!(full.managed_return, Some(Value::I32(expected)), "{case:?}");
            assert_eq!(objects(&full), stream_count, "{case:?}");
            assert_eq!(full.arrays.objects, array_count, "{case:?}");
            if matches!(case, CilFixture::StreamFile) {
                assert_eq!(full.artifacts.len(), 1);
                assert_eq!(full.artifacts[0].data, b"R");
                assert_eq!(full.artifacts[0].observations.len(), 2);
            } else {
                assert!(
                    full.artifacts.is_empty(),
                    "Raw guest stream buffers alone are not captures"
                );
            }
            assert_eq!(full.framework.attempts, full.framework.completed_calls);
            for budget in 1..full.instruction_count {
                let partial = run_fixture(arch, case, 1, budget).unwrap();
                assert_eq!(partial.instruction_count, budget, "{case:?}");
                assert_eq!(partial.completion_reason, "instruction_budget", "{case:?}");
                assert_eq!(partial.managed_return, None);
                if matches!(case, CilFixture::StreamFile) {
                    assert_eq!(partial.artifacts.len(), usize::from(budget >= 7));
                } else {
                    assert!(partial.artifacts.is_empty());
                }
                let streams = partial.framework.streams.as_ref();
                assert!(streams.is_none_or(|s| s.objects <= stream_count));
            }
            match case {
                CilFixture::StreamBorrowedWrite | CilFixture::StreamBorrowedRead => {
                    assert_eq!(bytes(&full, 0), [81, 66, 67])
                }
                CilFixture::StreamToArrayCopy => {
                    assert_eq!(bytes(&full, 0), [65, 66, 67]);
                    assert_eq!(bytes(&full, 1), [81, 66, 67]);
                }
                CilFixture::StreamSparse => assert_eq!(bytes(&full, 0), [0, 0, 0, 0, 0, 82]),
                CilFixture::StreamShrink => {
                    assert_eq!(bytes(&full, 0), [65, 0, 0]);
                    assert_eq!(bytes(&full, 1), [65, 0, 0]);
                }
                CilFixture::StreamRead => assert_eq!(bytes(&full, 1), [0, 65, 66]),
                CilFixture::StreamObjectArray => assert_eq!(
                    full.arrays.evidence[0].preview,
                    [Value::ObjectRef {
                        reference: 1,
                        kind: ObjectKind::MemoryStream
                    }]
                ),
                CilFixture::StreamObjectArrayKinds => assert_eq!(
                    full.arrays.evidence[0].preview,
                    [
                        Value::StringRef(1),
                        Value::ArrayRef {
                            reference: 2,
                            element: ArrayKind::U1
                        },
                        Value::ObjectRef {
                            reference: 1,
                            kind: ObjectKind::MemoryStream
                        }
                    ]
                ),
                CilFixture::StreamStaticCall => {
                    assert_eq!(full.managed_calls, 1);
                    assert_eq!(full.max_call_depth, 2);
                }
                CilFixture::StreamEmptyWrite => {
                    let state = &full.framework.streams.as_ref().unwrap().evidence[0];
                    assert_eq!(state.length, 0);
                    assert_eq!(state.position, 5);
                }
                _ => {}
            }
        }
    }
}
#[test]
fn invalid_newobj_and_stream_calls_fail_explicitly_and_keep_allocations_atomic() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (case, error, count) in [
            (CilFixture::StreamReadOnly, "NotSupportedException", 1),
            (CilFixture::StreamFixed, "fixed MemoryStream capacity", 1),
            (CilFixture::StreamClosedRead, "ObjectDisposedException", 1),
            (CilFixture::StreamClosedCan, "ObjectDisposedException", 1),
            (CilFixture::StreamSelfCopy, "same stream", 1),
            (CilFixture::StreamNullBuffer, "ArgumentNullException", 0),
            (CilFixture::StreamBadFlag, "writable flag", 0),
            (
                CilFixture::StreamBadCapacity,
                "ArgumentOutOfRangeException",
                0,
            ),
            (CilFixture::StreamBadSignature, "method/signature", 0),
            (CilFixture::StreamBadAssembly, "assembly/type", 0),
            (CilFixture::StreamBadVersion, "assembly/type", 0),
            (CilFixture::StreamBadNamespace, "namespace", 0),
            (CilFixture::StreamBadOwner, "MemberRef owner", 0),
            (CilFixture::StreamBadScope, "AssemblyRef", 0),
            (CilFixture::StreamConstructorCall, "require newobj", 1),
            (CilFixture::StreamConstructorStack, "max_stack", 0),
            (CilFixture::StreamNullReceiver, "NullReferenceException", 0),
            (CilFixture::StreamExposure, "method/signature", 1),
            (CilFixture::StreamUnknownClass, "Class identity", 1),
            (
                CilFixture::StreamObjectBadValue,
                "store value type mismatch",
                0,
            ),
            (CilFixture::StreamToArrayLimit, "array element limit", 1),
        ] {
            let result = run_fixture(arch, case, 1, 1000).unwrap();
            assert_eq!(result.completion_reason, "error", "{case:?}");
            assert!(result.error.as_ref().unwrap().contains(error), "{case:?}");
            assert_eq!(objects(&result), count, "{case:?}");
            assert!(result.managed_return.is_none());
            assert!(result.artifacts.is_empty());
            if matches!(
                case,
                CilFixture::StreamReadOnly | CilFixture::StreamFixed | CilFixture::StreamSelfCopy
            ) {
                assert_eq!(bytes(&result, 0), [65, 66, 67]);
            }
            if matches!(case, CilFixture::StreamObjectBadValue) {
                assert_eq!(result.arrays.evidence[0].preview, [Value::Null]);
                assert_eq!(result.arrays.element_writes, 0);
            }
        }
    }
}
#[test]
fn actual_constructor_quotas_have_bounded_evidence_and_no_failed_identity() {
    for arch in [Architecture::X86, Architecture::X64] {
        let quota = run_fixture(arch, CilFixture::StreamQuota, 1, 100_000).unwrap();
        assert_eq!(quota.completion_reason, "error");
        assert!(
            quota
                .error
                .as_ref()
                .unwrap()
                .contains("MemoryStream object limit")
        );
        assert_eq!(quota.instruction_count, 12289);
        assert_eq!(quota.framework.completed_calls, 4096);
        assert_eq!(quota.framework.attempts, 4097);
        let summary = quota.framework.streams.unwrap();
        assert_eq!(summary.objects, 4096);
        assert_eq!(summary.owned_capacity, 0);
        assert_eq!(summary.evidence.len(), 64);
        assert!(summary.evidence_truncated);
        assert_eq!(quota.framework.events.len(), 128);
        let bytes = run_fixture(arch, CilFixture::StreamOwnedQuota, 1, 100).unwrap();
        assert_eq!(bytes.completion_reason, "error");
        assert!(
            bytes
                .error
                .as_ref()
                .unwrap()
                .contains("owned capacity limit")
        );
        assert_eq!(bytes.instruction_count, 8);
        assert_eq!(bytes.framework.completed_calls, 2);
        assert_eq!(bytes.framework.attempts, 3);
        let summary = bytes.framework.streams.unwrap();
        assert_eq!(summary.objects, 2);
        assert_eq!(summary.owned_capacity, 64 * 1024 * 1024);
    }
}

#[test]
fn declared_class_local_metadata_still_fails_closed_before_execution() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut image = cil_probe(arch, CilFixture::StreamBaseLocal, 1);
        let locations: Vec<_> = image
            .windows(8)
            .enumerate()
            .filter_map(|(at, bytes)| (bytes == b"mscorlib").then_some(at))
            .collect();
        assert!(!locations.is_empty());
        for at in locations {
            image[at..at + 8].copy_from_slice(b"GuestApp");
        }
        let metadata = Metadata::parse(&image, "owned-invalid-class.exe").unwrap();
        let failure = Vm::for_method(&metadata, 0x06000001, Vec::new())
            .err()
            .expect("invalid declared Class must fail entry preflight");
        assert!(
            failure.to_string().contains("reference assembly/version"),
            "{failure:#}"
        );
        let mut classes = Classes::default();
        let declared = Type::Class(0x01000002);
        assert!(classes.validate(&metadata, &declared).is_err());
        assert!(!classes.accepts(Value::Null, &declared));
        assert!(!classes.accepts(
            Value::ObjectRef {
                reference: 1,
                kind: ObjectKind::MemoryStream
            },
            &declared
        ));
    }
}
