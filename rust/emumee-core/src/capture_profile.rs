//! Compiled capture limits. Selecting these is not execution authorization.
use serde::Serialize;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProfile {
    #[default]
    Legacy32V1,
    Driver128V1,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Limits {
    pub single: usize,
    pub retained: usize,
    pub scan: usize,
    pub work: u64,
    pub observations: usize,
    pub metadata: usize,
    pub chunk: usize,
}
impl CaptureProfile {
    pub fn limits(self) -> Limits {
        let mib = 1024 * 1024;
        Limits {
            single: if self == Self::Driver128V1 {
                128 * mib
            } else {
                32 * mib
            },
            retained: if self == Self::Driver128V1 {
                256 * mib
            } else {
                128 * mib
            },
            scan: 128 * mib,
            work: if self == Self::Driver128V1 {
                1024 * mib as u64
            } else {
                256 * mib as u64
            },
            observations: 10000,
            metadata: mib,
            chunk: 8 * mib,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiled_profiles_keep_legacy_exact_and_large_explicit() {
        let old = CaptureProfile::default().limits();
        assert_eq!(
            (old.single, old.retained, old.scan, old.work),
            (33554432, 134217728, 134217728, 268435456)
        );
        let new = CaptureProfile::Driver128V1.limits();
        assert_eq!(
            (new.single, new.retained, new.scan, new.work),
            (134217728, 268435456, 134217728, 1073741824)
        );
        assert_eq!(new.chunk, 8388608);
    }
}
