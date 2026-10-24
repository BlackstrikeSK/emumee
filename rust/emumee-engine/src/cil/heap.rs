//! Guest string identities and UTF16 storage. Never exposes a host pointer or CLR.
use anyhow::{Result, anyhow, ensure};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};

const MAX_STRINGS: usize = 65_536;
const MAX_UNITS: usize = 8 * 1024 * 1024;

#[derive(Default)]
pub(super) struct Heap {
    strings: Vec<Arc<[u16]>>,
    interned: BTreeMap<Arc<[u16]>, u32>,
    units: usize,
}
#[derive(Debug, Serialize)]
pub struct StringEvidence {
    pub reference: u32,
    pub utf16_length: usize,
    pub utf16_preview: Vec<u16>,
    pub preview_truncated: bool,
}
#[derive(Debug, Serialize)]
pub struct HeapSummary {
    pub string_objects: usize,
    pub utf16_units: usize,
    pub string_object_limit: usize,
    pub utf16_unit_limit: usize,
    pub strings: Vec<StringEvidence>,
    pub evidence_truncated: bool,
}
impl Heap {
    pub fn literal(&mut self, units: Vec<u16>) -> Result<u32> {
        if let Some(reference) = self.interned.get(units.as_slice()) {
            return Ok(*reference);
        }
        let reference = self.allocate(units)?;
        let value = Arc::clone(&self.strings[reference as usize - 1]);
        self.interned.insert(value, reference);
        Ok(reference)
    }
    pub fn ensure_capacity(&self, units: usize) -> Result<()> {
        ensure!(
            self.strings.len() < MAX_STRINGS,
            "Managed string object limit exceeded"
        );
        ensure!(
            units <= MAX_UNITS - self.units,
            "Managed UTF16 heap limit exceeded"
        );
        Ok(())
    }
    pub fn allocate(&mut self, units: Vec<u16>) -> Result<u32> {
        self.ensure_capacity(units.len())?;
        self.units += units.len();
        let units: Arc<[u16]> = units.into();
        let reference = self.strings.len() as u32 + 1;
        self.strings.push(units);
        Ok(reference)
    }
    pub fn string(&self, reference: u32) -> Result<&[u16]> {
        self.strings
            .get(reference.wrapping_sub(1) as usize)
            .map(AsRef::as_ref)
            .ok_or_else(|| anyhow!("Invalid guest managed string reference"))
    }
    pub fn describe(&self) -> HeapSummary {
        HeapSummary {
            string_objects: self.strings.len(),
            utf16_units: self.units,
            string_object_limit: MAX_STRINGS,
            utf16_unit_limit: MAX_UNITS,
            strings: self
                .strings
                .iter()
                .take(64)
                .enumerate()
                .map(|(index, units)| StringEvidence {
                    reference: index as u32 + 1,
                    utf16_length: units.len(),
                    utf16_preview: units.iter().take(64).copied().collect(),
                    preview_truncated: units.len() > 64,
                })
                .collect(),
            evidence_truncated: self.strings.len() > 64,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_allocations_preserve_distinct_identity_from_interned_literals() {
        let mut heap = Heap::default();
        let literal = heap.literal(vec![65]).unwrap();
        let first = heap.allocate(vec![65]).unwrap();
        let second = heap.allocate(vec![65]).unwrap();
        assert_ne!(literal, first);
        assert_ne!(first, second);
        assert_eq!(heap.literal(vec![65]).unwrap(), literal);
        assert_eq!(heap.string(first).unwrap(), [65]);
        assert!(heap.string(0).is_err());
        assert!(heap.string(u32::MAX).is_err());
    }
    #[test]
    fn string_literals_intern_by_code_units_without_lossy_unicode_conversion() {
        let mut heap = Heap::default();
        let first = heap.literal(vec![0x41, 0xd800, 0, 0xdc00]).unwrap();
        assert_eq!(first, heap.literal(vec![0x41, 0xd800, 0, 0xdc00]).unwrap());
        assert_ne!(first, heap.literal(vec![0x41, 0xfffd, 0, 0xdc00]).unwrap());
        let empty = heap.literal(Vec::new()).unwrap();
        assert_ne!(empty, 0);
        assert_eq!(empty, heap.literal(Vec::new()).unwrap());
        let report = heap.describe();
        assert_eq!(report.string_objects, 3);
        assert_eq!(report.utf16_units, 8);
        assert_eq!(report.strings[0].utf16_preview, [0x41, 0xd800, 0, 0xdc00]);
    }
    #[test]
    fn heap_limits_and_report_previews_remain_bounded() {
        let mut heap = Heap::default();
        let text = vec![65; MAX_UNITS];
        let reference = heap.literal(text.clone()).unwrap();
        assert_eq!(heap.literal(text).unwrap(), reference);
        assert!(
            heap.literal(vec![66])
                .unwrap_err()
                .to_string()
                .contains("heap limit")
        );
        let report = heap.describe();
        assert_eq!(report.strings[0].utf16_preview.len(), 64);
        assert!(report.strings[0].preview_truncated);
        let mut heap = Heap::default();
        for n in 0..MAX_STRINGS as u32 {
            heap.literal(vec![n as u16, (n >> 16) as u16]).unwrap();
        }
        assert!(
            heap.literal(vec![1, 1])
                .unwrap_err()
                .to_string()
                .contains("object limit")
        );
        assert!(heap.describe().evidence_truncated);
        assert_eq!(heap.describe().strings.len(), 64);
    }
}
