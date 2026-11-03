//! Bounds for the pinned capture's optional stack, driver-list and code data.
//! Offsets describe in-buffer records; their source addresses remain untrusted.
use super::{CAPTURE_BYTES, Error, u32_at, u64_at};
use std::ops::Range;

const FIRST_OPTIONAL: usize = 0x102f8;
const TRAILER: usize = CAPTURE_BYTES - 4;
const DRIVER_BYTES: usize = 0x90;

#[derive(Clone, Copy, Debug)]
pub struct StackCapture<'a> {
    pub source_address: u64,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct LoadedModule<'a> {
    /// Raw pinned triage record, including the in-buffer name offset.
    pub(super) record: &'a [u8],
    /// UTF-16 bytes excluding the native zero terminator. Not validated text.
    pub(super) name_utf16: &'a [u8],
}
impl<'a> LoadedModule<'a> {
    pub fn record(&self) -> &'a [u8] {
        self.record
    }
    pub fn name_utf16(&self) -> &'a [u8] {
        self.name_utf16
    }
    pub fn image_base(&self) -> u64 {
        u64_at(self.record, 0x38)
    }
    /// Native triage size, copied from the pinned loader's unrounded field.
    pub fn image_size(&self) -> u32 {
        u32_at(self.record, 0x48)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CodeRegion<'a> {
    pub source_address: u64,
    pub bytes: &'a [u8],
}

#[derive(Debug)]
pub(super) struct Records {
    pub stack: Option<Range<usize>>,
    pub modules: Vec<(Range<usize>, Range<usize>)>,
    pub code: Option<Range<usize>>,
    pub code_source: u64,
}

fn align8(value: usize) -> Result<usize, Error> {
    value
        .checked_add(7)
        .map(|n| n & !7)
        .ok_or(Error::Bounds("optional alignment"))
}

fn span(start: u32, size: usize, label: &'static str) -> Result<Range<usize>, Error> {
    let start = start as usize;
    let end = start.checked_add(size).ok_or(Error::Bounds(label))?;
    if start < FIRST_OPTIONAL || end > TRAILER {
        return Err(Error::Bounds(label));
    }
    Ok(start..end)
}

impl Records {
    pub fn parse(bytes: &[u8], flags: u32) -> Result<Self, Error> {
        let mut result = Self {
            stack: None,
            modules: Vec::new(),
            code: None,
            code_source: 0,
        };
        let mut next = FIRST_OPTIONAL;
        if flags & 0x20 != 0 {
            let size = u32_at(bytes, 0x202c) as usize;
            if size == 0 || size > 0x7fff {
                return Err(Error::Layout("stack length"));
            }
            let stack = span(u32_at(bytes, 0x2028), size, "stack")?;
            if stack.start != next {
                return Err(Error::Layout("stack offset"));
            }
            next = stack.end;
            result.stack = Some(stack);
        }
        if flags & 0x40 != 0 {
            let count = u32_at(bytes, 0x2034) as usize;
            let size = count
                .checked_mul(DRIVER_BYTES)
                .ok_or(Error::Bounds("driver list"))?;
            if count == 0 {
                return Err(Error::Layout("empty driver list"));
            }
            let table = span(u32_at(bytes, 0x2030), size, "driver list")?;
            if table.start != align8(next)? {
                return Err(Error::Layout("driver list offset"));
            }
            let names = span(
                u32_at(bytes, 0x2038),
                u32_at(bytes, 0x203c) as usize,
                "driver names",
            )?;
            if names.start != table.end || names.len() & 7 != 0 {
                return Err(Error::Layout("driver names offset or length"));
            }
            let mut name_at = names.start;
            for record_at in (table.start..table.end).step_by(DRIVER_BYTES) {
                if u32_at(bytes, record_at) as usize != name_at {
                    return Err(Error::Layout("driver name offset"));
                }
                let prefix_end = name_at.checked_add(4).ok_or(Error::Bounds("driver name"))?;
                if prefix_end > names.end {
                    return Err(Error::Bounds("driver name"));
                }
                let units = u32_at(bytes, name_at) as usize;
                let length = units.checked_mul(2).ok_or(Error::Bounds("driver name"))?;
                let end = prefix_end
                    .checked_add(length)
                    .ok_or(Error::Bounds("driver name"))?;
                let terminator_end = end.checked_add(2).ok_or(Error::Bounds("driver name"))?;
                if terminator_end > names.end || bytes[end..terminator_end] != [0, 0] {
                    return Err(Error::Bounds("driver name or terminator"));
                }
                result
                    .modules
                    .push((record_at..record_at + DRIVER_BYTES, prefix_end..end));
                name_at = align8(terminator_end)?;
            }
            if name_at > names.end {
                return Err(Error::Bounds("driver names"));
            }
            next = names.end;
        }
        if flags & 0x800 != 0 {
            if u32_at(bytes, 0x207c) != 1 {
                return Err(Error::Layout("code region count"));
            }
            let header = span(u32_at(bytes, 0x2078), 0x10, "code region header")?;
            if header.start != align8(next)? {
                return Err(Error::Layout("code region offset"));
            }
            let length = u32_at(bytes, header.start + 0xc) as usize;
            if length == 0 || length > 0x1000 {
                return Err(Error::Layout("code region length"));
            }
            let data = span(u32_at(bytes, header.start + 8), length, "code region")?;
            if data.start != header.end {
                return Err(Error::Layout("code data offset"));
            }
            result.code_source = u64_at(bytes, header.start);
            result.code = Some(data);
        }
        Ok(result)
    }
}
