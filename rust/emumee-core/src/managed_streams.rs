//! Pure bounded guest MemoryStream state. No host Stream, CLR or filesystem.
use serde::Serialize;
pub const MAX_LENGTH: usize = 32 * 1024 * 1024;
pub const MAX_OBJECTS: usize = 4096;
pub const MAX_OWNED: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    #[error("Invalid guest MemoryStream identity")]
    Identity,
    #[error("Invalid guest MemoryStream byte-array backing")]
    Array,
    #[error("System.ObjectDisposedException; managed exception dispatch is not yet modeled")]
    Closed,
    #[error(
        "System.NotSupportedException: stream is read-only; managed exception dispatch is not yet modeled"
    )]
    ReadOnly,
    #[error("System.ArgumentOutOfRangeException; managed exception dispatch is not yet modeled")]
    Range,
    #[error("System.ArgumentException: seek origin; managed exception dispatch is not yet modeled")]
    Origin,
    #[error(
        "System.IO.IOException: seek outside bounded stream; managed exception dispatch is not yet modeled"
    )]
    Seek,
    #[error(
        "System.NotSupportedException: fixed MemoryStream capacity; managed exception dispatch is not yet modeled"
    )]
    Fixed,
    #[error("CopyTo on the same stream is unsupported")]
    SelfCopy,
    #[error("Managed MemoryStream object limit exceeded")]
    ObjectLimit,
    #[error("Managed MemoryStream owned capacity limit exceeded")]
    StorageLimit,
    #[error("Managed MemoryStream length limit exceeded")]
    LengthLimit,
}
pub type Result<T> = std::result::Result<T, StreamError>;
pub trait ByteArrays {
    fn bytes(&self, reference: u32) -> Result<&[u8]>;
    fn bytes_mut(&mut self, reference: u32) -> Result<&mut [u8]>;
}
enum Buffer {
    Owned(Vec<u8>),
    Array { reference: u32, capacity: usize },
}
struct Stream {
    buffer: Buffer,
    length: usize,
    position: usize,
    writable: bool,
    closed: bool,
}
impl Stream {
    fn open(&self) -> Result<()> {
        if self.closed {
            Err(StreamError::Closed)
        } else {
            Ok(())
        }
    }
    fn writeable(&self) -> Result<()> {
        self.open()?;
        if self.writable {
            Ok(())
        } else {
            Err(StreamError::ReadOnly)
        }
    }
    fn capacity(&self) -> usize {
        match &self.buffer {
            Buffer::Owned(v) => v.len(),
            Buffer::Array { capacity, .. } => *capacity,
        }
    }
    fn bytes<'a>(&'a self, arrays: &'a impl ByteArrays) -> Result<&'a [u8]> {
        match &self.buffer {
            Buffer::Owned(v) => Ok(v),
            Buffer::Array {
                reference,
                capacity,
            } => {
                let bytes = arrays.bytes(*reference)?;
                if bytes.len() != *capacity {
                    return Err(StreamError::Array);
                }
                Ok(bytes)
            }
        }
    }
    fn bytes_mut<'a>(&'a mut self, arrays: &'a mut impl ByteArrays) -> Result<&'a mut [u8]> {
        match &mut self.buffer {
            Buffer::Owned(v) => Ok(v),
            Buffer::Array {
                reference,
                capacity,
            } => {
                let bytes = arrays.bytes_mut(*reference)?;
                if bytes.len() != *capacity {
                    return Err(StreamError::Array);
                }
                Ok(bytes)
            }
        }
    }
}
#[derive(Default)]
pub struct Streams {
    objects: Vec<Stream>,
    owned: usize,
}
#[derive(Debug, Serialize)]
pub struct Evidence {
    pub reference: u32,
    pub length: usize,
    pub position: usize,
    pub capacity: usize,
    pub borrowed_array: Option<u32>,
    pub expandable: bool,
    pub writable: bool,
    pub closed: bool,
    pub exposable: bool,
}
#[derive(Debug, Serialize)]
pub struct Summary {
    pub objects: usize,
    pub owned_capacity: usize,
    pub object_limit: usize,
    pub owned_capacity_limit: usize,
    pub length_position_limit: usize,
    pub evidence: Vec<Evidence>,
    pub evidence_truncated: bool,
    pub scope: &'static str,
}
fn range(offset: i32, count: i32, length: usize) -> Result<std::ops::Range<usize>> {
    if offset < 0 || count < 0 {
        return Err(StreamError::Range);
    }
    let start = offset as usize;
    let end = start
        .checked_add(count as usize)
        .ok_or(StreamError::Range)?;
    if end > length {
        return Err(StreamError::Range);
    }
    Ok(start..end)
}
impl Streams {
    fn object(&self, id: u32) -> Result<&Stream> {
        self.objects
            .get(id.wrapping_sub(1) as usize)
            .ok_or(StreamError::Identity)
    }
    fn object_mut(&mut self, id: u32) -> Result<&mut Stream> {
        self.objects
            .get_mut(id.wrapping_sub(1) as usize)
            .ok_or(StreamError::Identity)
    }
    fn slot(&self) -> Result<()> {
        if self.objects.len() >= MAX_OBJECTS {
            Err(StreamError::ObjectLimit)
        } else {
            Ok(())
        }
    }
    pub fn valid(&self, id: u32) -> Result<()> {
        self.object(id).map(|_| ())
    }
    pub fn owned(&mut self, capacity: i32) -> Result<u32> {
        if capacity < 0 || capacity as usize > MAX_LENGTH {
            return Err(StreamError::Range);
        }
        self.slot()?;
        let capacity = capacity as usize;
        if capacity > MAX_OWNED - self.owned {
            return Err(StreamError::StorageLimit);
        }
        self.objects.push(Stream {
            buffer: Buffer::Owned(vec![0; capacity]),
            length: 0,
            position: 0,
            writable: true,
            closed: false,
        });
        self.owned += capacity;
        Ok(self.objects.len() as u32)
    }
    pub fn borrowed(
        &mut self,
        reference: u32,
        writable: bool,
        arrays: &impl ByteArrays,
    ) -> Result<u32> {
        let capacity = arrays.bytes(reference)?.len();
        if capacity > MAX_LENGTH {
            return Err(StreamError::LengthLimit);
        }
        self.slot()?;
        self.objects.push(Stream {
            buffer: Buffer::Array {
                reference,
                capacity,
            },
            length: capacity,
            position: 0,
            writable,
            closed: false,
        });
        Ok(self.objects.len() as u32)
    }
    pub fn length(&self, id: u32) -> Result<usize> {
        let s = self.object(id)?;
        s.open()?;
        Ok(s.length)
    }
    pub fn position(&self, id: u32) -> Result<usize> {
        let s = self.object(id)?;
        s.open()?;
        Ok(s.position)
    }
    pub fn capability(&self, id: u32, write: bool) -> Result<bool> {
        let s = self.object(id)?;
        s.open()?;
        Ok(!write || s.writable)
    }
    pub fn set_position(&mut self, id: u32, position: i64) -> Result<()> {
        let s = self.object_mut(id)?;
        s.open()?;
        if !(0..=MAX_LENGTH as i64).contains(&position) {
            return Err(StreamError::Range);
        }
        s.position = position as usize;
        Ok(())
    }
    pub fn seek(&mut self, id: u32, offset: i64, origin: i32) -> Result<usize> {
        let s = self.object_mut(id)?;
        s.open()?;
        let base = match origin {
            0 => 0,
            1 => s.position,
            2 => s.length,
            _ => return Err(StreamError::Origin),
        } as i64;
        let position = base.checked_add(offset).ok_or(StreamError::Seek)?;
        if !(0..=MAX_LENGTH as i64).contains(&position) {
            return Err(StreamError::Seek);
        }
        s.position = position as usize;
        Ok(s.position)
    }
    pub fn close(&mut self, id: u32) -> Result<()> {
        self.object_mut(id)?.closed = true;
        Ok(())
    }
    pub fn flush(&self, id: u32) -> Result<()> {
        self.object(id)?.open()
    }
    /// Caller preflights its returned byte-array capacity before asking for a copy.
    pub fn array_length(&self, id: u32) -> Result<usize> {
        Ok(self.object(id)?.length)
    }
    pub fn to_array(&self, id: u32, arrays: &impl ByteArrays) -> Result<Vec<u8>> {
        let s = self.object(id)?;
        Ok(s.bytes(arrays)?[..s.length].to_vec())
    }
    fn grow(&mut self, id: u32, end: usize, arrays: &impl ByteArrays) -> Result<()> {
        let s = self.object(id)?;
        s.bytes(arrays)?;
        if end > MAX_LENGTH {
            return Err(StreamError::LengthLimit);
        }
        let capacity = s.capacity();
        if end <= capacity {
            return Ok(());
        }
        if matches!(s.buffer, Buffer::Array { .. }) {
            return Err(StreamError::Fixed);
        }
        let new_capacity = end.max(capacity.saturating_mul(2)).clamp(256, MAX_LENGTH);
        let extra = new_capacity - capacity;
        if extra > MAX_OWNED - self.owned {
            return Err(StreamError::StorageLimit);
        }
        let s = self.object_mut(id)?;
        let Buffer::Owned(old) = &mut s.buffer else {
            unreachable!()
        };
        let mut buffer = vec![0; new_capacity];
        buffer[..old.len()].copy_from_slice(old);
        *old = buffer;
        self.owned += extra;
        Ok(())
    }
    pub fn set_length(&mut self, id: u32, length: i64, arrays: &mut impl ByteArrays) -> Result<()> {
        self.object(id)?.writeable()?;
        if !(0..=MAX_LENGTH as i64).contains(&length) {
            return Err(StreamError::Range);
        }
        let length = length as usize;
        self.grow(id, length, arrays)?;
        let s = self.object_mut(id)?;
        let old = s.length;
        if length > old {
            s.bytes_mut(arrays)?[old..length].fill(0)
        }
        s.length = length;
        s.position = s.position.min(length);
        Ok(())
    }
    pub fn read_byte(&mut self, id: u32, arrays: &impl ByteArrays) -> Result<i32> {
        let s = self.object(id)?;
        s.open()?;
        if s.position >= s.length {
            return Ok(-1);
        }
        let byte = s.bytes(arrays)?[s.position];
        self.object_mut(id)?.position += 1;
        Ok(byte as i32)
    }
    pub fn read(
        &mut self,
        id: u32,
        reference: u32,
        offset: i32,
        count: i32,
        arrays: &mut impl ByteArrays,
    ) -> Result<usize> {
        let s = self.object(id)?;
        s.open()?;
        let destination = range(offset, count, arrays.bytes(reference)?.len())?;
        let length = (count as usize).min(s.length.saturating_sub(s.position));
        let bytes = if length == 0 {
            Vec::new()
        } else {
            s.bytes(arrays)?[s.position..s.position + length].to_vec()
        };
        arrays.bytes_mut(reference)?[destination.start..destination.start + length]
            .copy_from_slice(&bytes);
        self.object_mut(id)?.position += length;
        Ok(length)
    }
    fn write_bytes(&mut self, id: u32, bytes: &[u8], arrays: &mut impl ByteArrays) -> Result<()> {
        let s = self.object(id)?;
        s.writeable()?;
        if bytes.is_empty() {
            return Ok(());
        } // retained legacy zero-count sparse-write behavior
        let position = s.position;
        let length = s.length;
        let end = position
            .checked_add(bytes.len())
            .ok_or(StreamError::LengthLimit)?;
        self.grow(id, end, arrays)?;
        let s = self.object_mut(id)?;
        let buffer = s.bytes_mut(arrays)?;
        if position > length {
            buffer[length..position].fill(0)
        }
        buffer[position..end].copy_from_slice(bytes);
        s.length = length.max(end);
        s.position = end;
        Ok(())
    }
    pub fn write(
        &mut self,
        id: u32,
        reference: u32,
        offset: i32,
        count: i32,
        arrays: &mut impl ByteArrays,
    ) -> Result<()> {
        self.object(id)?.writeable()?;
        let bytes = arrays.bytes(reference)?;
        let source = range(offset, count, bytes.len())?;
        // Only the requested span is snapshotted, making backing-array overlap safe.
        let copy = bytes[source].to_vec();
        self.write_bytes(id, &copy, arrays)
    }
    pub fn write_byte(&mut self, id: u32, value: i32, arrays: &mut impl ByteArrays) -> Result<()> {
        if !(0..=255).contains(&value) {
            return Err(StreamError::Range);
        }
        self.write_bytes(id, &[value as u8], arrays)
    }
    pub fn copy_to(
        &mut self,
        source: u32,
        target: u32,
        buffer_size: Option<i32>,
        arrays: &mut impl ByteArrays,
    ) -> Result<usize> {
        if let Some(size) = buffer_size {
            if size <= 0 {
                return Err(StreamError::Range);
            }
        }
        if source == target {
            return Err(StreamError::SelfCopy);
        }
        let s = self.object(source)?;
        s.open()?;
        self.object(target)?.writeable()?;
        let count = s.length.saturating_sub(s.position);
        let bytes = if count == 0 {
            Vec::new()
        } else {
            s.bytes(arrays)?[s.position..s.length].to_vec()
        };
        self.write_bytes(target, &bytes, arrays)?;
        self.object_mut(source)?.position += count;
        Ok(count)
    }
    pub fn describe(&self) -> Summary {
        Summary {
            objects: self.objects.len(),
            owned_capacity: self.owned,
            object_limit: MAX_OBJECTS,
            owned_capacity_limit: MAX_OWNED,
            length_position_limit: MAX_LENGTH,
            evidence: self
                .objects
                .iter()
                .take(64)
                .enumerate()
                .map(|(index, s)| Evidence {
                    reference: index as u32 + 1,
                    length: s.length,
                    position: s.position,
                    capacity: s.capacity(),
                    borrowed_array: match s.buffer {
                        Buffer::Array { reference, .. } => Some(reference),
                        _ => None,
                    },
                    expandable: matches!(s.buffer, Buffer::Owned(_)),
                    writable: s.writable,
                    closed: s.closed,
                    exposable: matches!(s.buffer, Buffer::Owned(_)),
                })
                .collect(),
            evidence_truncated: self.objects.len() > 64,
            scope: "Bounded guest MemoryStream identities; borrowed byte[] aliases stay in guest arrays. Legacy closed-capability and zero-count sparse-write behavior retained. Exposable flag records policy; GetBuffer/TryGetBuffer remain unsupported. No host streams or managed exception dispatch.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Arrays(Vec<Vec<u8>>);
    impl ByteArrays for Arrays {
        fn bytes(&self, id: u32) -> Result<&[u8]> {
            self.0
                .get(id.wrapping_sub(1) as usize)
                .map(Vec::as_slice)
                .ok_or(StreamError::Array)
        }
        fn bytes_mut(&mut self, id: u32) -> Result<&mut [u8]> {
            self.0
                .get_mut(id.wrapping_sub(1) as usize)
                .map(Vec::as_mut_slice)
                .ok_or(StreamError::Array)
        }
    }
    #[test]
    fn owned_sparse_write_shrink_extend_and_legacy_empty_write_preserve_state() {
        let mut arrays = Arrays(vec![vec![]]);
        let mut s = Streams::default();
        let id = s.owned(10).unwrap();
        s.set_position(id, 5).unwrap();
        s.write(id, 1, 0, 0, &mut arrays).unwrap();
        assert_eq!(s.length(id), Ok(0));
        assert_eq!(s.position(id), Ok(5));
        s.write_byte(id, 82, &mut arrays).unwrap();
        assert_eq!(s.to_array(id, &arrays).unwrap(), [0, 0, 0, 0, 0, 82]);
        s.set_length(id, 2, &mut arrays).unwrap();
        assert_eq!(s.position(id), Ok(2));
        s.set_length(id, 6, &mut arrays).unwrap();
        assert_eq!(s.to_array(id, &arrays).unwrap(), [0; 6]);
        s.set_position(id, 10).unwrap();
        assert_eq!(s.read_byte(id, &arrays), Ok(-1));
        assert_eq!(s.position(id), Ok(10));
        s.close(id).unwrap();
        s.close(id).unwrap();
        assert_eq!(s.to_array(id, &arrays).unwrap(), [0; 6]);
        assert_eq!(s.capability(id, false), Err(StreamError::Closed));
        assert_eq!(s.flush(id), Err(StreamError::Closed));
    }
    #[test]
    fn borrowed_aliasing_readonly_and_overlapping_copies_use_actual_array() {
        let mut arrays = Arrays(vec![b"ABCDE".to_vec(), vec![0; 5]]);
        let mut s = Streams::default();
        let first = s.borrowed(1, true, &arrays).unwrap();
        let readonly = s.borrowed(1, false, &arrays).unwrap();
        arrays.bytes_mut(1).unwrap()[0] = b'Q';
        assert_eq!(s.read_byte(readonly, &arrays), Ok(b'Q' as i32));
        s.set_position(first, 1).unwrap();
        s.write(first, 1, 0, 4, &mut arrays).unwrap();
        assert_eq!(arrays.bytes(1).unwrap(), b"QQBCD");
        s.set_position(first, 0).unwrap();
        assert_eq!(s.read(first, 1, 1, 4, &mut arrays), Ok(4));
        assert_eq!(arrays.bytes(1).unwrap(), b"QQQBC");
        assert_eq!(
            s.write_byte(readonly, 1, &mut arrays),
            Err(StreamError::ReadOnly)
        );
        s.set_position(first, 0).unwrap();
        assert_eq!(
            s.copy_to(first, readonly, None, &mut arrays),
            Err(StreamError::ReadOnly)
        );
        assert_eq!(s.position(first), Ok(0));
        assert_eq!(s.position(readonly), Ok(1));
        assert_eq!(
            s.copy_to(first, first, None, &mut arrays),
            Err(StreamError::SelfCopy)
        );
        let mut snapshot = s.to_array(first, &arrays).unwrap();
        snapshot[0] = 0;
        assert_eq!(arrays.bytes(1).unwrap()[0], b'Q');
    }
    #[test]
    fn fixed_growth_bad_ranges_seek_and_constructor_failures_are_atomic() {
        let mut arrays = Arrays(vec![b"ABC".to_vec()]);
        let mut s = Streams::default();
        let id = s.borrowed(1, true, &arrays).unwrap();
        s.set_position(id, 3).unwrap();
        assert_eq!(s.write_byte(id, 7, &mut arrays), Err(StreamError::Fixed));
        assert_eq!(s.to_array(id, &arrays).unwrap(), b"ABC");
        assert_eq!(s.position(id), Ok(3));
        assert_eq!(s.seek(id, i64::MAX, 1), Err(StreamError::Seek));
        assert_eq!(s.position(id), Ok(3));
        assert_eq!(s.read(id, 1, -1, 1, &mut arrays), Err(StreamError::Range));
        assert_eq!(
            s.write(id, 1, 0, i32::MAX, &mut arrays),
            Err(StreamError::Range)
        );
        assert_eq!(s.owned(-1), Err(StreamError::Range));
        assert_eq!(s.borrowed(99, true, &arrays), Err(StreamError::Array));
        assert_eq!(s.describe().objects, 1);
        assert_eq!(s.describe().owned_capacity, 0);
        assert_eq!(s.owned(0), Ok(2));
        s.set_length(id, 1, &mut arrays).unwrap();
        s.set_length(id, 3, &mut arrays).unwrap();
        assert_eq!(arrays.bytes(1).unwrap(), [65, 0, 0]);
    }
    #[test]
    fn object_capacity_and_preview_limits_hold_without_cloning_catalogs() {
        let mut s = Streams::default();
        for _ in 0..MAX_OBJECTS {
            s.owned(0).unwrap();
        }
        assert_eq!(s.owned(0), Err(StreamError::ObjectLimit));
        assert_eq!(s.describe().objects, MAX_OBJECTS);
        assert_eq!(s.describe().evidence.len(), 64);
        assert!(s.describe().evidence_truncated);
        let mut s = Streams::default();
        s.owned(MAX_LENGTH as i32).unwrap();
        s.owned(MAX_LENGTH as i32).unwrap();
        assert_eq!(s.owned(1), Err(StreamError::StorageLimit));
        assert_eq!(s.describe().objects, 2);
        assert_eq!(s.describe().owned_capacity, MAX_OWNED);
        assert_eq!(s.valid(0), Err(StreamError::Identity));
    }
}
