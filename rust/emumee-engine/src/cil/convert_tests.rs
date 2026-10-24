use super::*;

#[test]
fn convert_guest_arrays_identity_binary_mutation_and_every_short_budget() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (case, value, instructions, calls, arrays, strings) in [
            (CilFixture::ConvertBytes, 5, 5, 1, 1, 1),
            (CilFixture::ConvertWhitespace, 5, 5, 1, 1, 1),
            (CilFixture::ConvertEmpty, 0, 5, 1, 1, 1),
            (CilFixture::ConvertTrailingBits, 1, 5, 1, 1, 1),
            (CilFixture::ConvertIdentity, 0, 6, 2, 2, 1),
            (CilFixture::ConvertWritable, 82, 9, 1, 1, 1),
            (CilFixture::ConvertRoundTrip, 1, 6, 3, 1, 2),
            (CilFixture::ConvertEncodeEmpty, 1, 6, 3, 1, 2),
            (CilFixture::ConvertFile, 17, 6, 2, 1, 2),
        ] {
            for budget in 1..=instructions {
                let result = run_fixture(arch, case, 1, budget).unwrap();
                assert_eq!(result.instruction_count, budget, "{case:?}");
                assert_eq!(
                    result.framework.events.len() as u64 + result.framework.omitted_events,
                    result.framework.attempts
                );
                if budget == instructions {
                    assert_eq!(
                        result.completion_reason, "entry_return",
                        "{case:?}: {:?}",
                        result.error
                    );
                    assert_eq!(result.managed_return, Some(Value::I32(value)), "{case:?}");
                    assert_eq!(result.framework.completed_calls, calls, "{case:?}");
                    assert_eq!(result.arrays.objects, arrays, "{case:?}");
                    assert_eq!(result.heap.string_objects, strings, "{case:?}");
                    if matches!(case, CilFixture::ConvertFile) {
                        assert_eq!(result.artifacts.len(), 1);
                        assert_eq!(result.artifacts[0].data, [0, 255, 128, 77, 90]);
                        assert_eq!(result.artifacts[0].observations.len(), 2);
                        assert!(
                            result.artifacts[0]
                                .observations
                                .iter()
                                .all(|o| o.kind == emumee_core::artifacts::ArtifactKind::GuestFile)
                        );
                    } else {
                        assert!(result.artifacts.is_empty());
                    }
                } else {
                    assert_eq!(result.completion_reason, "instruction_budget", "{case:?}");
                    assert_eq!(result.managed_return, None);
                    if matches!(case, CilFixture::ConvertFile) {
                        assert_eq!(result.artifacts.len(), usize::from(budget >= 4));
                    }
                }
            }
        }
        let binary = run_fixture(arch, CilFixture::ConvertBytes, 1, 100).unwrap();
        assert_eq!(binary.arrays.evidence[0].element, ArrayKind::U1);
        assert_eq!(
            binary.arrays.evidence[0].preview,
            [0, 255, 128, 77, 90].map(Value::I32)
        );
        let writable = run_fixture(arch, CilFixture::ConvertWritable, 1, 100).unwrap();
        assert_eq!(writable.arrays.evidence[0].preview[0], Value::I32(82));
        assert_eq!(writable.arrays.element_writes, 1);
        assert_eq!(writable.arrays.element_reads, 1);
    }
}
#[test]
fn convert_rejects_bad_metadata_signatures_nulls_utf16_and_actual_wrong_arrays() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (case, error, instructions, arrays) in [
            (CilFixture::ConvertMalformed, "FormatException", 2, 0),
            (CilFixture::ConvertPadding, "FormatException", 2, 0),
            (CilFixture::ConvertUnicode, "FormatException", 2, 0),
            (CilFixture::ConvertSurrogate, "FormatException", 2, 0),
            (CilFixture::ConvertNull, "ArgumentNullException", 2, 0),
            (CilFixture::ConvertNullBytes, "ArgumentNullException", 2, 0),
            (
                CilFixture::ConvertBadArgument,
                "argument type mismatch",
                2,
                0,
            ),
            (
                CilFixture::ConvertWrongArray,
                "argument type mismatch",
                3,
                1,
            ),
            (CilFixture::ConvertBadSignature, "method/signature", 2, 0),
            (CilFixture::ConvertBadAssembly, "assembly/type", 2, 0),
            (CilFixture::ConvertBadVersion, "assembly/type", 2, 0),
            (CilFixture::ConvertBadNamespace, "namespace", 2, 0),
            (CilFixture::ConvertBadOwner, "MemberRef owner", 2, 0),
            (CilFixture::ConvertBadScope, "AssemblyRef", 2, 0),
            (
                CilFixture::ConvertStaticVirtual,
                "static framework method",
                2,
                0,
            ),
        ] {
            let result = run_fixture(arch, case, 1, 100).unwrap();
            assert_eq!(result.completion_reason, "error", "{case:?}");
            assert!(result.error.unwrap().contains(error), "{case:?}");
            assert_eq!(result.instruction_count, instructions, "{case:?}");
            assert_eq!(result.framework.attempts, 1);
            assert_eq!(result.framework.completed_calls, 0);
            assert_eq!(result.arrays.objects, arrays);
            assert_eq!(result.managed_return, None);
            assert!(result.artifacts.is_empty());
        }
    }
}
#[test]
fn convert_resource_limits_preserve_counts_and_never_allocate_past_capacity() {
    for arch in [Architecture::X86, Architecture::X64] {
        let quota = run_fixture(arch, CilFixture::ConvertQuota, 1, 100_000).unwrap();
        assert_eq!(quota.completion_reason, "error");
        assert!(quota.error.unwrap().contains("array object limit"));
        assert_eq!(quota.arrays.objects, 4096);
        assert_eq!(quota.arrays.storage_bytes, 0);
        assert_eq!(quota.framework.completed_calls, 4096);
        assert_eq!(quota.framework.attempts, 4097);
        assert_eq!(quota.instruction_count, 16386);
        let heap = run_fixture(arch, CilFixture::ConvertHeapQuota, 1, 400_000).unwrap();
        assert_eq!(heap.completion_reason, "error");
        assert!(heap.error.unwrap().contains("string object limit"));
        assert_eq!(heap.heap.string_objects, 65536);
        assert_eq!(heap.heap.utf16_units, 0);
        assert_eq!(heap.arrays.objects, 1);
        assert_eq!(heap.framework.completed_calls, 65536);
        assert_eq!(heap.framework.attempts, 65537);
        assert_eq!(heap.instruction_count, 262148);
        let limit = run_fixture(arch, CilFixture::ConvertDecodeLimit, 1, 1000).unwrap();
        assert_eq!(limit.completion_reason, "error");
        assert!(limit.error.unwrap().contains("array element limit"));
        assert_eq!(limit.arrays.objects, 0);
        assert_eq!(limit.heap.string_objects, 20);
        assert_eq!(limit.framework.completed_calls, 19);
        assert_eq!(limit.framework.attempts, 20);
        assert_eq!(limit.heap.utf16_units, 4_194_300);
        assert_eq!(limit.instruction_count, 156);
        let large = run_fixture(arch, CilFixture::ConvertLargeEncode, 1, 100).unwrap();
        assert_eq!(large.completion_reason, "entry_return", "{:?}", large.error);
        assert_eq!(large.managed_return, Some(Value::I32(17)));
        assert_eq!(large.arrays.objects, 1);
        assert_eq!(large.arrays.storage_bytes, 1_048_576);
        assert_eq!(large.heap.utf16_units, 1_398_104);
        assert_eq!(large.heap.string_objects, 1);
        assert_eq!(large.instruction_count, 6);
        assert_eq!(large.heap.strings[0].utf16_preview, vec![65; 64]);
    }
}
