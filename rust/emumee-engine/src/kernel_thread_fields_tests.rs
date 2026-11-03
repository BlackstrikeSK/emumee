//! Harmless native guest controls for individually projected thread fields.
use super::*;
use emumee_core::fixtures::{ApiFixture, ThreadObjectFixture};
const BASE: u64 = 0x140000000;
struct Code {
    bytes: Vec<u8>,
    origin: u32,
}
impl Code {
    fn new(origin: u32) -> Self {
        Self {
            bytes: vec![0x48, 0x83, 0xec, 0x68],
            origin,
        }
    }
    fn emit(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes);
    }
    fn call(&mut self, index: usize) {
        self.emit(&[0xff, 0x15]);
        let next = self.origin as i64 + self.bytes.len() as i64 + 4;
        self.emit(&((0x2080 + index * 8) as i64 - next).to_le_bytes()[..4]);
    }
    fn value(&mut self, prefix: &[u8], value: u64) {
        self.emit(prefix);
        self.emit(&value.to_le_bytes());
    }
    fn expect(&mut self, value: u32) {
        self.emit(&[0x3d]);
        self.emit(&value.to_le_bytes());
        self.emit(&[0x74, 2, 0x0f, 0x0b]);
    }
    fn thread(&mut self) {
        self.emit(&[0x65, 0x4c, 0x8b, 0x14, 0x25, 0x88, 1, 0, 0]);
    }
    fn check(&mut self, depth: u16) {
        self.call(17);
        self.thread(); // PID agrees with ETHREAD.Cid.UniqueProcess.
        self.emit(&[0x49, 0x3b, 0x82, 8, 5, 0, 0, 0x74, 2, 0x0f, 0x0b]);
        self.expect(4);
        self.call(18);
        self.thread();
        self.emit(&[0x49, 0x3b, 0x82, 0x10, 5, 0, 0, 0x74, 2, 0x0f, 0x0b]);
        self.call(19);
        self.thread();
        self.emit(&[
            0x41, 0x0f, 0xbe, 0x92, 0x32, 2, 0, 0, 0x39, 0xd0, 0x74, 2, 0x0f, 0x0b,
        ]);
        self.expect(0);
        self.thread();
        self.emit(&[0x41, 0x0f, 0xb7, 0x82, 0xe4, 1, 0, 0]);
        self.expect(u32::from(0u16.wrapping_sub(depth)));
        self.call(22);
        self.expect(u32::from(depth != 0));
    }
    fn returned(&mut self, value: u32) {
        self.emit(&[0xb8]);
        self.emit(&value.to_le_bytes());
        self.emit(&[0x48, 0x83, 0xc4, 0x68, 0xc3]);
    }
}
fn image() -> Vec<u8> {
    let mut image = emumee_core::fixtures::api_probe(
        Architecture::X64,
        ApiFixture::ThreadObjects(ThreadObjectFixture::RootHeader),
    );
    for (i, name) in [
        "PsGetCurrentProcessId",
        "PsGetCurrentThreadId",
        "ExGetPreviousMode",
        "KeEnterCriticalRegion",
        "KeLeaveCriticalRegion",
        "KeAreApcsDisabled",
    ]
    .into_iter()
    .enumerate()
    {
        let i = i + 17;
        let name_at = 0x1500 + i * 64;
        image[name_at..name_at + 64].fill(0);
        image[name_at + 2..name_at + 2 + name.len()].copy_from_slice(name.as_bytes());
        let rva = 0x2300u64 + i as u64 * 64;
        image[0x1280 + i * 8..0x1288 + i * 8].copy_from_slice(&rva.to_le_bytes());
        image[0x1380 + i * 8..0x1388 + i * 8].copy_from_slice(&rva.to_le_bytes());
    }
    let mut root = Code::new(0x1000);
    root.check(0);
    root.call(20);
    root.check(1);
    root.call(20);
    root.check(2);
    root.value(&[0x48, 0xb9], BASE + 0x2c00); // output handle
    root.emit(&[
        0xba, 0xff, 0xff, 0x1f, 0, 0x45, 0x31, 0xc0, 0x45, 0x31, 0xc9,
    ]);
    root.value(&[0x48, 0xb8], BASE + 0x2c50);
    root.emit(&[0x48, 0x89, 0x44, 0x24, 0x20]);
    root.value(&[0x48, 0xb8], BASE + 0x1c00);
    root.emit(&[0x48, 0x89, 0x44, 0x24, 0x28]);
    root.emit(&[0x48, 0xc7, 0x44, 0x24, 0x30, 0, 0, 0, 0]);
    root.call(1);
    root.expect(0);
    // Enough actual native instructions for cooperative preemption while root
    // remains inside its critical region; child must still start at depth1.
    root.emit(&[0xb9, 0, 2, 0, 0, 0xff, 0xc9, 0x75, 0xfc]);
    root.check(2);
    root.call(21);
    root.check(1);
    root.call(21);
    root.check(0);
    let child_object =
        emumee_core::kernel_layout::KernelLayout::for_architecture(Architecture::X64)
            .thread_object(2)
            .unwrap();
    root.value(&[0x48, 0xb9], child_object);
    root.emit(&[
        0x31, 0xd2, 0x45, 0x31, 0xc0, 0x45, 0x31, 0xc9, 0x48, 0xc7, 0x44, 0x24, 0x20, 0, 0, 0, 0,
    ]);
    root.call(5);
    root.expect(0);
    root.value(&[0x48, 0xa1], BASE + 0x2c00);
    root.emit(&[0x48, 0x89, 0xc1]);
    root.call(3);
    root.expect(0);
    root.returned(1);
    let mut child = Code::new(0x1c00);
    child.check(1);
    child.call(20);
    child.check(2);
    child.call(21);
    child.check(1);
    child.call(21);
    child.check(0);
    child.returned(0);
    assert!(root.bytes.len() < 0xc00 && child.bytes.len() < 0x400);
    image[0x200..0xe00].fill(0xcc);
    image[0xe00..0x1200].fill(0xcc);
    image[0x200..0x200 + root.bytes.len()].copy_from_slice(&root.bytes);
    image[0xe00..0xe00 + child.bytes.len()].copy_from_slice(&child.bytes);
    image
}
#[test]
fn owned_thread_fields_agree_with_apis_across_nested_regions_and_child_switches() {
    let image = image();
    let e = super::kernel_thread_objects_tests::run_pinned_thread_image_budget(26200, &image, 5000);
    assert_eq!(e.error, None, "{e:#?}");
    assert_eq!(e.guest_entry_return, Some(1));
    let report = e.kernel_thread_objects.as_ref().unwrap();
    assert!(report.private_accesses.is_empty());
    assert_eq!(report.thread_fields.len(), 1);
    assert_eq!(report.thread_fields[0].raw_kernel_apc_disable, 0);
    assert!(
        report
            .threads
            .iter()
            .any(|thread| thread.slot == 2 && thread.retired)
    );
    for tid in [1, 2] {
        assert!(
            e.api_events.iter().any(
                |event| event.api == "ntoskrnl.KeEnterCriticalRegion" && event.thread_id == tid
            )
        );
    }
    let other =
        super::kernel_thread_objects_tests::run_pinned_thread_image_budget(26100, &image, 5000);
    assert!(other.error.is_some());
    assert_eq!(other.guest_entry_return, None);
    assert!(
        other
            .kernel_thread_objects
            .unwrap()
            .thread_fields
            .is_empty()
    );
}
#[test]
fn owned_thread_fields_refuse_unknown_halves_crossing_reads_and_native_writes() {
    for (offset, size, write) in [
        (0x1e4, 4, false),
        (0x1e6, 2, false),
        (0x1e3, 2, false),
        (0x232, 2, false),
        (0x507, 8, false),
        (0x511, 8, false),
        (0x1e4, 2, true),
        (0x232, 1, true),
        (0x508, 8, true),
    ] {
        let mut image = image();
        let mut code = Code::new(0x1000);
        code.thread();
        match (size, write) {
            (1, true) => code.emit(&[0x41, 0xc6, 0x82]),
            (2, true) => code.emit(&[0x66, 0x41, 0xc7, 0x82]),
            (8, true) => code.emit(&[0x49, 0xc7, 0x82]),
            (2, false) => code.emit(&[0x41, 0x0f, 0xb7, 0x82]),
            (4, false) => code.emit(&[0x41, 0x8b, 0x82]),
            (8, false) => code.emit(&[0x49, 0x8b, 0x82]),
            _ => panic!("unsupported probe width"),
        }
        code.emit(&(offset as u32).to_le_bytes());
        if write {
            code.emit(&vec![0; if size == 8 { 4 } else { size }]);
        }
        code.returned(1);
        image[0x200..0x200 + code.bytes.len()].copy_from_slice(&code.bytes);
        let e =
            super::kernel_thread_objects_tests::run_pinned_thread_image_budget(26200, &image, 1000);
        assert_eq!(
            e.guest_entry_return, None,
            "{offset:x}/{size}/{write}: {e:#?}"
        );
        let error = e.error.unwrap();
        assert!(
            error.contains("private or released kernel thread body")
                || write && error.contains("WRITE_PROT"),
            "{error}"
        );
    }
}
