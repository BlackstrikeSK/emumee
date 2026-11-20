//! Forced section unmap control family. Enumeration and injection are what an
//! analysis runtime exists to observe, so this family proves the unmap really
//! happens and that the run report attributes it.
use super::*;
use emumee_core::fixtures::{M6UnmapFixture as U, m6_unmap_child, m6_unmap_probe};

fn control(arch: Architecture, kind: U) -> Execution {
    let label = format!("{arch:?}-m6-unmap-{kind:?}");
    let staged = [Staged {
        kind: InputKind::File,
        path: r"C:\emumee\child.exe",
        bytes: m6_unmap_child(arch),
    }];
    let result = run(&label, m6_unmap_probe(arch, kind), &staged, 60_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m6_forced_unmap_removes_a_mapped_image_and_is_recorded_as_an_observation() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, U::SelfImage);
        assert_eq!(result.forced_unmaps.len(), 1, "{:#?}", result.forced_unmaps);
        let unmapped = &result.forced_unmaps[0];
        assert_eq!(unmapped.process_id, 1024);
        assert_eq!(unmapped.name, "kernel32.dll");
        // The caller's own primary image is untouched, so this is not the
        // hollowing signature.
        assert!(!unmapped.was_primary);
        assert!(unmapped.size > 0);
        // The image really left the catalog rather than being reported gone.
        assert!(
            !result
                .loaded_modules
                .iter()
                .any(|module| module.name == "kernel32.dll"),
            "{:#?}",
            result.loaded_modules
        );
    }
}

#[test]
fn m6_forced_unmap_refuses_every_address_that_is_not_a_mapped_section_base() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, U::NotMapped);
        assert!(result.forced_unmaps.is_empty(), "{:#?}", result.forced_unmaps);
        assert!(
            result
                .loaded_modules
                .iter()
                .any(|module| module.name == "kernel32.dll")
        );
    }
}

#[test]
fn m6_unmapping_a_suspended_child_primary_image_is_the_hollowing_signature() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, U::Hollow);
        assert_eq!(result.forced_unmaps.len(), 1, "{:#?}", result.forced_unmaps);
        let unmapped = &result.forced_unmaps[0];
        // Attributed to the process whose address space held the image, not to
        // the caller, and flagged as that process's own primary image.
        assert_eq!(unmapped.process_id, 1025);
        assert!(unmapped.was_primary);
        assert_eq!(unmapped.name, "child.exe");
        let child = result.user_processes.iter().find(|p| p.id == 1025).unwrap();
        assert_eq!(child.failure, None, "{child:#?}");
    }
}
