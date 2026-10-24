use super::*;
#[test]
fn guest_tid_matches_real_client_id_and_source_remote_processor_thread_lifetimes() {
    for arch in [Architecture::X86, Architecture::X64] {
        let full =
            run_api_fixture(arch, emumee_core::fixtures::ApiFixture::GuestTid, 10000).unwrap();
        assert_eq!(
            full.completion_reason, "entry_return",
            "{arch:?}: {:?} pc={:#x}",
            full.error, full.final_pc
        );
        assert_eq!(full.guest_entry_return, Some(17));
        let lives = &full.kernel_thread_objects.as_ref().unwrap().threads;
        let ipi = full.kernel_ipi.as_ref().unwrap();
        let identity_calls = full
            .api_events
            .iter()
            .filter(|e| e.api == "ntoskrnl.PsGetCurrentThreadId")
            .collect::<Vec<_>>();
        assert!(identity_calls.len() >= 4);
        for event in identity_calls {
            let life = lives
                .iter()
                .find(|l| l.address == event.current_thread)
                .unwrap();
            assert_eq!(event.result, Some(life.guest_id));
            assert_ne!(life.guest_id, 0);
        }
        let ids = lives
            .iter()
            .map(|l| l.guest_id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids.len(), lives.len());
        let child = lives.iter().find(|l| l.slot == 2).unwrap();
        assert_eq!(child.guest_id, 0x1008);
        assert!(child.terminated && child.retired && child.open_handles == 0);
        assert_eq!(full.kernel_threads.as_ref().unwrap().count, 2);
        // A real IPI completed after the child exited; remote IDs are their own
        // borrowed object identities, and CPU0 retains the interrupted caller.
        assert!(!ipi.native_effect_failure);
        assert_eq!(ipi.rendezvous.broadcasts.len(), 1);
        let broadcast = &ipi.rendezvous.broadcasts[0];
        assert!(broadcast.completed);
        assert_eq!(broadcast.members.len(), 12);
        assert_eq!(broadcast.source_result, Some(0x1004));
        for member in &broadcast.members {
            let expected = if member.processor == 0 {
                0x1004
            } else {
                0x2000 + u64::from(member.processor) * 4
            };
            assert_eq!(member.result, Some(expected));
            assert!(member.started && member.instruction_count > 0);
        }
        let prefix = run_api_fixture(
            arch,
            emumee_core::fixtures::ApiFixture::GuestTid,
            full.instruction_count - 1,
        )
        .unwrap();
        assert_eq!(prefix.completion_reason, "instruction_budget");
        assert_eq!(prefix.guest_entry_return, None);
        assert!(prefix.error.is_none());
        assert_eq!(prefix.api_calls, full.api_calls);
    }
}
