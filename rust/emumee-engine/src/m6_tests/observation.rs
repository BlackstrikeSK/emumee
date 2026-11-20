//! Instruction, cache and protection observation control family. The image
//! observation is passive: it must see every write into the sample's own image
//! without changing a single guest instruction, permission or result.
use super::*;
use emumee_core::fixtures::{M6ObservationFixture as O, m6_observation_probe};

/// Distinct image bytes the observation recorded a write to.
fn touched_bytes(report: &crate::image_writes::Report) -> u32 {
    report
        .watched_regions
        .iter()
        .flat_map(|region| region.touched_byte_bitmap.iter())
        .map(|byte| byte.count_ones())
        .sum()
}

fn control(arch: Architecture, kind: O) -> Execution {
    let label = format!("{arch:?}-m6-observation-{kind:?}");
    let result = run(&label, m6_observation_probe(arch, kind), &[], 60_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m6_writes_inside_a_submitted_sample_image_are_observed_byte_for_byte() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, O::ImageWrite);
        let report = result.image_writes.as_ref().unwrap();
        let base = if arch == Architecture::X64 {
            0x140000000
        } else {
            0x400000
        };
        assert_eq!(report.image_base, base);
        assert!(report.image_size > 0);
        assert!(report.omitted_regions.is_empty(), "{report:#?}");
        assert_eq!(report.observations_omitted, 0);
        // Six guest writes landed in the watched data section: four distinct
        // words, one overwrite of the first of them, and the word the control
        // poisons before its refused protection request.
        assert_eq!(report.native_overlapping_attempts, 6, "{report:#?}");
        assert_eq!(report.model_overlapping_writes, 0, "{report:#?}");
        // The overwrite reuses bytes already recorded, so twenty distinct
        // bytes were touched rather than twenty-four.
        assert_eq!(touched_bytes(report), 20, "{report:#?}");
    }
}

#[test]
fn m6_guest_written_instructions_run_and_rewriting_them_invalidates_the_cache() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, O::WrittenCode);
        // The written code is in a private reservation, not in the image, so
        // the image observation saw nothing at all.
        let report = result.image_writes.as_ref().unwrap();
        // Only one write touched the image at all: the pointer-width slot the
        // control saved the region's own address into.
        assert_eq!(report.native_overlapping_attempts, 1, "{report:#?}");
        assert_eq!(report.model_overlapping_writes, 0, "{report:#?}");
        assert_eq!(
            touched_bytes(report),
            if arch == Architecture::X64 { 8 } else { 4 },
            "{report:#?}"
        );
    }
}
