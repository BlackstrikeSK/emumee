//! Checked view of the pinned AMD64 persistent-triage capture layout.
//!
//! Parsing establishes bounds and format only. It does not establish that a
//! kernel produced the bytes, that referenced objects exist, or that a caller
//! supplied a valid hardware CONTEXT. In-place context/output aliasing can leave
//! PAGE fill in the copied context even in the native implementation.
use serde::Serialize;
use std::ops::Range;
use thiserror::Error;
pub mod admission;
pub mod boot;
mod optional;
pub use optional::{CodeRegion, LoadedModule, StackCapture};

pub const CAPTURE_BYTES: usize = 0x40000;
pub const CONTEXT_OFFSET: usize = 0x348;
pub const CONTEXT_BYTES: usize = 0x4d0;
pub const DEBUGGER_DATA_OFFSET: usize = 0x2080;
pub const DEBUGGER_DATA_BYTES: usize = 0x3a0;
pub const PROCESSOR_OFFSET: usize = 0x2420;
pub const PROCESSOR_BYTES: usize = 0xcf00;
pub const PROCESS_OFFSET: usize = 0xf320;
pub const PROCESS_BYTES: usize = 0x840;
pub const THREAD_OFFSET: usize = 0xfb60;
pub const THREAD_BYTES: usize = 0x798;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("Persistent capture is truncated")]
    Truncated,
    #[error("Persistent capture signature, architecture or dump kind is unsupported")]
    Format,
    #[error("Persistent capture record is out of bounds: {0}")]
    Bounds(&'static str),
    #[error("Persistent capture layout is unsupported: {0}")]
    Layout(&'static str),
    #[error("Persistent capture debugger-data header is invalid")]
    DebuggerHeader,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Metadata {
    pub bytes: usize,
    pub major_version: u32,
    pub minor_version: u32,
    pub processor_count: u32,
    pub directory_table_base: u64,
    pub loaded_module_list: u64,
    pub active_process_head: u64,
    pub bugcheck_code: u32,
    pub bugcheck_parameters: [u64; 4],
    /// Native global address from the dump header, not the in-buffer copy.
    pub debugger_data_address: u64,
    pub kernel_base: u64,
    pub debugger_data_offset: usize,
    pub debugger_data_bytes: usize,
    pub captured_records: u32,
}

#[derive(Debug)]
pub struct Capture<'a> {
    bytes: &'a [u8],
    metadata: Metadata,
    optional: optional::Records,
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn record(offset: u32, length: usize, name: &'static str) -> Result<Range<usize>, Error> {
    let start = offset as usize;
    let end = start.checked_add(length).ok_or(Error::Bounds(name))?;
    if end > CAPTURE_BYTES {
        return Err(Error::Bounds(name));
    }
    Ok(start..end)
}

impl<'a> Capture<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, Error> {
        let bytes = input.get(..CAPTURE_BYTES).ok_or(Error::Truncated)?;
        if &bytes[..4] != b"PAGE"
            || &bytes[4..8] != b"DU64"
            || u32_at(bytes, 0x30) != 0x8664
            || u32_at(bytes, 0xf98) != 4
            || &bytes[CAPTURE_BYTES - 4..] != b"TRGD"
        {
            return Err(Error::Format);
        }
        if u64_at(bytes, 0xfa0) != CAPTURE_BYTES as u64
            || u32_at(bytes, 0x2004) != CAPTURE_BYTES as u32
            || u32_at(bytes, 0x2008) != (CAPTURE_BYTES - 4) as u32
        {
            return Err(Error::Layout("size or trailer offset"));
        }
        let records = u32_at(bytes, 0x1038);
        if records & 0x49f != 0x49f {
            return Err(Error::Layout(
                "required context/debugger/processor/object records",
            ));
        }
        // Fixed native records are adjacent, not interchangeable. Do not turn
        // an in-bounds alias into a valid alternative version of the format.
        for (field, expected, length, name) in [
            (0x200c, CONTEXT_OFFSET, CONTEXT_BYTES, "context"),
            (0x2010, 0xf00, 0x98, "exception"),
            (0x201c, PROCESSOR_OFFSET, PROCESSOR_BYTES, "processor"),
            (0x2020, PROCESS_OFFSET, PROCESS_BYTES, "process"),
            (0x2024, THREAD_OFFSET, THREAD_BYTES, "thread"),
        ] {
            let span = record(u32_at(bytes, field), length, name)?;
            if span.start != expected {
                return Err(Error::Layout(name));
            }
        }
        let debugger_bytes = u32_at(bytes, 0x2074) as usize;
        let debugger = record(u32_at(bytes, 0x2070), debugger_bytes, "debugger data")?;
        if debugger.start != DEBUGGER_DATA_OFFSET || debugger_bytes != DEBUGGER_DATA_BYTES {
            return Err(Error::Layout("debugger data"));
        }
        let data = &bytes[debugger.clone()];
        if &data[0x10..0x14] != b"KDBG" || u32_at(data, 0x14) != DEBUGGER_DATA_BYTES as u32 {
            return Err(Error::DebuggerHeader);
        }
        let metadata = Metadata {
            bytes: CAPTURE_BYTES,
            major_version: u32_at(bytes, 8),
            minor_version: u32_at(bytes, 0xc),
            processor_count: u32_at(bytes, 0x34),
            directory_table_base: u64_at(bytes, 0x10),
            loaded_module_list: u64_at(bytes, 0x20),
            active_process_head: u64_at(bytes, 0x28),
            bugcheck_code: u32_at(bytes, 0x38),
            bugcheck_parameters: [0x40, 0x48, 0x50, 0x58].map(|at| u64_at(bytes, at)),
            debugger_data_address: u64_at(bytes, 0x80),
            kernel_base: u64_at(data, 0x18),
            debugger_data_offset: debugger.start,
            debugger_data_bytes: debugger_bytes,
            captured_records: records,
        };
        let optional = optional::Records::parse(bytes, records)?;
        Ok(Self {
            bytes,
            metadata,
            optional,
        })
    }
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn context(&self) -> &'a [u8] {
        &self.bytes[CONTEXT_OFFSET..CONTEXT_OFFSET + CONTEXT_BYTES]
    }
    pub fn debugger_data(&self) -> &'a [u8] {
        &self.bytes[DEBUGGER_DATA_OFFSET..DEBUGGER_DATA_OFFSET + DEBUGGER_DATA_BYTES]
    }
    pub fn processor(&self) -> &'a [u8] {
        &self.bytes[PROCESSOR_OFFSET..PROCESSOR_OFFSET + PROCESSOR_BYTES]
    }
    pub fn process(&self) -> &'a [u8] {
        &self.bytes[PROCESS_OFFSET..PROCESS_OFFSET + PROCESS_BYTES]
    }
    pub fn thread(&self) -> &'a [u8] {
        &self.bytes[THREAD_OFFSET..THREAD_OFFSET + THREAD_BYTES]
    }
    pub fn stack(&self) -> Option<StackCapture<'a>> {
        self.optional.stack.as_ref().map(|span| StackCapture {
            source_address: u64_at(self.bytes, 0x2048),
            bytes: &self.bytes[span.clone()],
        })
    }
    pub fn modules(&self) -> impl ExactSizeIterator<Item = LoadedModule<'a>> + '_ {
        self.optional
            .modules
            .iter()
            .map(|(record, name)| LoadedModule {
                record: &self.bytes[record.clone()],
                name_utf16: &self.bytes[name.clone()],
            })
    }
    pub fn code_region(&self) -> Option<CodeRegion<'a>> {
        self.optional.code.as_ref().map(|span| CodeRegion {
            source_address: self.optional.code_source,
            bytes: &self.bytes[span.clone()],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put32(b: &mut [u8], at: usize, value: u32) {
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn generated() -> Vec<u8> {
        let mut b = vec![0; CAPTURE_BYTES + 16];
        for (at, value) in [
            (0, 0x45474150),
            (4, 0x34365544),
            (8, 15),
            (0xc, 26200),
            (0x30, 0x8664),
            (0x34, 16),
            (0x38, 0x1234),
            (0xf98, 4),
            (0x1038, 0x49f),
            (0x2004, 0x40000),
            (0x2008, 0x3fffc),
            (0x200c, 0x348),
            (0x2010, 0xf00),
            (0x201c, 0x2420),
            (0x2020, 0xf320),
            (0x2024, 0xfb60),
            (0x2070, 0x2080),
            (0x2074, 0x3a0),
            (0x2090, 0x4742444b),
            (0x2094, 0x3a0),
            (0x3fffc, 0x44475254),
        ] {
            put32(&mut b, at, value);
        }
        for (at, value) in [
            (0x10, 0x12345000),
            (0x20, 0xffffa10000200000),
            (0x28, 0xffffa10000300000),
            (0x40, 1),
            (0x48, 2),
            (0x50, 3),
            (0x58, 4),
            (0x80, 0xfffff80001201060),
            (0xfa0, 0x40000),
            (0x2098, 0xfffff80000400000),
        ] {
            put64(&mut b, at, value);
        }
        b[CONTEXT_OFFSET..CONTEXT_OFFSET + CONTEXT_BYTES].fill(0x50);
        b[PROCESSOR_OFFSET..PROCESSOR_OFFSET + PROCESSOR_BYTES].fill(0x11);
        b[PROCESS_OFFSET..PROCESS_OFFSET + PROCESS_BYTES].fill(0x22);
        b[THREAD_OFFSET..THREAD_OFFSET + THREAD_BYTES].fill(0x33);
        b[CAPTURE_BYTES..].fill(0xa5);
        b
    }
    #[test]
    fn capture_layout_matches_versioned_native_and_sdk_measurements() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/native_capture_layout.json"
        ))
        .unwrap();
        assert_eq!(v["native_capture_bytes"], CAPTURE_BYTES);
        assert_eq!(v["native_debugger_data_bytes"], DEBUGGER_DATA_BYTES);
        assert_eq!(v["sdk_debugger_data_bytes"], 0x3a8);
        for (name, offset, length) in [
            ("context", CONTEXT_OFFSET, CONTEXT_BYTES),
            ("processor", PROCESSOR_OFFSET, PROCESSOR_BYTES),
            ("process", PROCESS_OFFSET, PROCESS_BYTES),
            ("thread", THREAD_OFFSET, THREAD_BYTES),
            ("debugger_data", DEBUGGER_DATA_OFFSET, DEBUGGER_DATA_BYTES),
        ] {
            assert_eq!(v["records"][name]["offset"], offset);
            assert_eq!(v["records"][name]["bytes"], length);
        }
    }
    #[test]
    fn capture_view_bounds_records_and_separates_global_address_from_copied_data() {
        let b = generated();
        let capture = Capture::parse(&b).unwrap();
        let m = capture.metadata();
        assert_eq!(m.debugger_data_address, 0xfffff80001201060);
        assert_eq!(m.kernel_base, 0xfffff80000400000);
        assert_eq!(m.bugcheck_parameters, [1, 2, 3, 4]);
        assert_eq!(m.minor_version, 26200);
        assert_eq!(capture.bytes().len(), CAPTURE_BYTES);
        assert_eq!(capture.context(), vec![0x50; CONTEXT_BYTES]);
        assert_eq!(capture.processor(), vec![0x11; PROCESSOR_BYTES]);
        assert_eq!(capture.process(), vec![0x22; PROCESS_BYTES]);
        assert_eq!(capture.thread(), vec![0x33; THREAD_BYTES]);
        assert_eq!(capture.debugger_data().len(), DEBUGGER_DATA_BYTES);
        assert_eq!(&b[CAPTURE_BYTES..], &[0xa5; 16]);
        // Context bytes are caller-supplied, not validated processor state.
        assert_eq!(u32_at(capture.context(), 0x30), 0x50505050);
    }
    #[test]
    fn capture_truncation_bad_signatures_architectures_and_record_aliases_are_rejected() {
        let b = generated();
        for n in [0, 7, 8192, CAPTURE_BYTES - 1] {
            assert_eq!(Capture::parse(&b[..n]).unwrap_err(), Error::Truncated);
        }
        for (at, value) in [(0, 0), (4, 0), (0x30, 0x14c), (0xf98, 1), (0x3fffc, 0)] {
            let mut bad = b.clone();
            put32(&mut bad, at, value);
            assert_eq!(Capture::parse(&bad).unwrap_err(), Error::Format);
        }
        for field in [0x200c, 0x2010, 0x201c, 0x2020, 0x2024, 0x2070] {
            for value in [0, 1, 0x3ffff, u32::MAX] {
                let mut bad = b.clone();
                put32(&mut bad, field, value);
                assert!(matches!(
                    Capture::parse(&bad),
                    Err(Error::Bounds(_) | Error::Layout(_))
                ));
            }
        }
    }
    #[test]
    fn capture_size_flags_and_debugger_header_cannot_silently_change_the_layout() {
        for (at, value) in [
            (0x2004, 0x80000),
            (0x2008, 0),
            (0x1038, 0x483),
            (0x2074, 0x3a8),
            (0x2074, u32::MAX),
            (0x2090, 0),
            (0x2094, 0x3a8),
        ] {
            let mut b = generated();
            put32(&mut b, at, value);
            assert!(Capture::parse(&b).is_err());
        }
        let mut b = generated();
        put64(&mut b, 0xfa0, 0);
        assert!(Capture::parse(&b).is_err());
    }
    fn with_optional_records() -> Vec<u8> {
        let mut b = generated();
        for (at, value) in [
            (0x1038, 0xcff),
            (0x2028, 0x102f8),
            (0x202c, 0x25),
            (0x2030, 0x10320),
            (0x2034, 2),
            (0x2038, 0x10440),
            (0x203c, 0x40),
            (0x2078, 0x10480),
            (0x207c, 1),
            (0x10320, 0x10440),
            (0x103b0, 0x10458),
            (0x10368, 0x3000),
            (0x10440, 9),
            (0x10458, 5),
            (0x10488, 0x10490),
            (0x1048c, 0x40),
        ] {
            put32(&mut b, at, value);
        }
        put64(&mut b, 0x2048, 0xffffa000000f0000);
        put64(&mut b, 0x10358, 0xfffff80000400000);
        put64(&mut b, 0x10480, 0xfffff80000401234);
        for (at, text) in [(0x10444, "alpha.sys"), (0x1045c, "β.sys")] {
            for (i, unit) in text.encode_utf16().enumerate() {
                b[at + i * 2..at + i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
            }
        }
        b[0x102f8..0x1031d].fill(0x5a);
        b[0x10490..0x104d0].fill(0xcc);
        b
    }
    #[test]
    fn capture_optional_views_follow_native_record_order_and_exclude_name_terminators() {
        let b = with_optional_records();
        let capture = Capture::parse(&b).unwrap();
        let stack = capture.stack().unwrap();
        assert_eq!(stack.source_address, 0xffffa000000f0000);
        assert_eq!(stack.bytes, &[0x5a; 0x25]);
        let mut modules = capture.modules();
        assert_eq!(modules.len(), 2);
        let first = modules.next().unwrap();
        assert_eq!(first.record().len(), 0x90);
        assert_eq!(first.image_base(), 0xfffff80000400000);
        assert_eq!(first.image_size(), 0x3000);
        assert_eq!(first.name_utf16(), b"a\0l\0p\0h\0a\0.\0s\0y\0s\0");
        assert_eq!(modules.next().unwrap().name_utf16().len(), 10);
        assert!(modules.next().is_none());
        let code = capture.code_region().unwrap();
        assert_eq!(code.source_address, 0xfffff80000401234);
        assert_eq!(code.bytes, &[0xcc; 0x40]);
        assert_eq!(&b[CAPTURE_BYTES..], &[0xa5; 16]);
    }
    #[test]
    fn capture_optional_declared_regions_cannot_escape_alias_or_overflow() {
        for (at, value) in [
            (0x2028, 0x102f9),
            (0x202c, 0),
            (0x202c, 0x8000),
            (0x2030, 0x102f8),
            (0x2034, 0),
            (0x2034, u32::MAX),
            (0x2038, 0x10320),
            (0x203c, 0),
            (0x203c, 1),
            (0x203c, u32::MAX),
            (0x10320, 0x348),
            (0x103b0, 0x10440),
            (0x10440, u32::MAX),
            (0x10456, 1),
            (0x2078, 0x10320),
            (0x2078, 0x3fffc),
            (0x207c, 0),
            (0x207c, 2),
            (0x10488, 0x1048c),
            (0x10488, 0x3fffc),
            (0x1048c, 0),
            (0x1048c, 0x1001),
            (0x1048c, u32::MAX),
        ] {
            let mut b = with_optional_records();
            put32(&mut b, at, value);
            assert!(Capture::parse(&b).is_err(), "field {at:x}, value {value:x}");
        }
    }
    #[test]
    fn capture_optional_flags_control_views_and_maximum_native_stack_length_is_valid() {
        let mut b = with_optional_records();
        put32(&mut b, 0x1038, 0x49f);
        put32(&mut b, 0x2034, u32::MAX);
        let capture = Capture::parse(&b).unwrap();
        assert!(capture.stack().is_none());
        assert_eq!(capture.modules().len(), 0);
        assert!(capture.code_region().is_none());
        put32(&mut b, 0x1038, 0x4bf);
        put32(&mut b, 0x202c, 0x7fff);
        assert_eq!(
            Capture::parse(&b).unwrap().stack().unwrap().bytes.len(),
            0x7fff
        );
    }
}
