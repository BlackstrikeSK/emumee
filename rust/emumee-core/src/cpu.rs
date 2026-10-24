//! Guest CPU identity. Host observations may be supplied explicitly in a validated persona.
use serde::Serialize;
use thiserror::Error;

#[derive(Clone, Debug, Serialize)]
pub struct CpuidOverride {
    pub function: u32,
    pub subleaf: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuProfile {
    pub brand: String,
    pub signature: u32,
    pub cores: u32,
    pub threads_per_core: u32,
    pub base_mhz: u32,
    pub max_mhz: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cpuid_overrides: Vec<CpuidOverride>,
}
#[derive(Debug, Error)]
#[error("Invalid guest CPU profile")]
pub struct InvalidCpuProfile;
impl Default for CpuProfile {
    fn default() -> Self {
        Self {
            brand: "Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz".into(),
            signature: 0x000a0653,
            cores: 6,
            threads_per_core: 2,
            base_mhz: 2900,
            max_mhz: 4300,
            cpuid_overrides: vec![],
        }
    }
}
impl CpuProfile {
    pub fn validate(&self) -> Result<(), InvalidCpuProfile> {
        if !self.brand.is_ascii()
            || self.brand.len() > 48
            || !(1..=32).contains(&self.cores)
            || !(1..=2).contains(&self.threads_per_core)
            || !(100..=6000).contains(&self.base_mhz)
            || !(self.base_mhz..=7000).contains(&self.max_mhz)
            || self.cpuid_overrides.len() > 64
            || self.cpuid_overrides.iter().enumerate().any(|(index, item)| {
                self.cpuid_overrides[..index].iter().any(|prior| {
                    prior.function == item.function && prior.subleaf == item.subleaf
                })
            })
        {
            return Err(InvalidCpuProfile);
        }
        Ok(())
    }
    /// Callers validate a profile before installing it into an engine.
    pub fn leaf(&self, function: u32, subleaf: u32, processor: u32) -> [u32; 4] {
        if let Some(item) = self
            .cpuid_overrides
            .iter()
            .find(|item| item.function == function && item.subleaf == subleaf)
        {
            // The local APIC ID is per logical processor, not a fixed identity byte.
            let ebx = if function == 1 {
                (item.ebx & 0x00ff_ffff) | ((processor & 255) << 24)
            } else {
                item.ebx
            };
            let edx = if function == 0xb || function == 0x1f {
                processor
            } else {
                item.edx
            };
            return [item.eax, ebx, item.ecx, edx];
        }
        let logical = self.cores * self.threads_per_core;
        match function {
            0 => [0x16, 0x756e6547, 0x6c65746e, 0x49656e69],
            1 => [
                self.signature,
                (processor & 255) << 24 | logical << 16 | 8 << 8,
                bits(&[
                    0, 1, 3, 5, 9, 12, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                ]),
                0xbfebfbff,
            ],
            4 => {
                let caches = [
                    (1, 1, 32 * 1024, 8, self.threads_per_core),
                    (2, 1, 32 * 1024, 8, self.threads_per_core),
                    (3, 2, 256 * 1024, 4, self.threads_per_core),
                    (3, 3, 12 * 1024 * 1024, 12, logical),
                ];
                match caches.get(subleaf as usize) {
                    Some(&(kind, level, size, ways, sharing)) => [
                        kind | level << 5 | (sharing - 1) << 14 | (self.cores - 1) << 26,
                        (ways - 1) << 22 | 63,
                        size / (ways * 64) - 1,
                        0,
                    ],
                    None => [0; 4],
                }
            }
            7 if subleaf == 0 => [
                0,
                bits(&[0, 1, 3, 5, 7, 8, 9, 10, 18, 19, 20, 23, 24, 29]),
                0,
                0,
            ],
            0xb => match subleaf {
                0 => [
                    32 - (self.threads_per_core - 1).leading_zeros(),
                    self.threads_per_core,
                    1 << 8,
                    processor,
                ],
                1 => [
                    32 - (logical - 1).leading_zeros(),
                    logical,
                    2 << 8 | 1,
                    processor,
                ],
                _ => [0, 0, 0, processor],
            },
            0xd => match subleaf {
                0 => [7, 832, 832, 0],
                1 => [1, 0, 0, 0],
                2 => [256, 576, 0, 0],
                _ => [0; 4],
            },
            0x15 => [24, self.base_mhz, 24_000_000, 0],
            0x16 => [self.base_mhz, self.max_mhz, 100, 0],
            0x80000000 => [0x80000008, 0, 0, 0],
            0x80000001 => [0, 0, 1, bits(&[11, 20, 27, 29])],
            0x80000002..=0x80000004 => {
                let mut brand = [b' '; 48];
                let bytes = self.brand.as_bytes();
                let len = bytes.len().min(48);
                brand[..len].copy_from_slice(&bytes[..len]);
                let offset = (function - 0x80000002) as usize * 16;
                std::array::from_fn(|i| {
                    u32::from_le_bytes(
                        brand[offset + i * 4..offset + i * 4 + 4]
                            .try_into()
                            .unwrap(),
                    )
                })
            }
            0x80000007 => [0, 0, 0, 1 << 8],
            0x80000008 => [39 | 48 << 8, 0, 0, 0],
            _ => [0; 4],
        }
    }
}
fn bits(indices: &[u32]) -> u32 {
    indices.iter().fold(0, |value, index| value | 1 << index)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persona_identity_topology_frequency_and_unknown_leaves() {
        let profile = CpuProfile::default();
        profile.validate().unwrap();
        let vendor = profile.leaf(0, 0, 0);
        let bytes: Vec<_> = [vendor[1], vendor[3], vendor[2]]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert_eq!(bytes, b"GenuineIntel");
        assert_eq!(profile.leaf(1, 0, 0)[0], 0xa0653);
        assert_eq!(profile.leaf(1, 0, 0)[1] >> 16, 12);
        assert_eq!(profile.leaf(0xb, 0, 0), [1, 2, 256, 0]);
        assert_eq!(profile.leaf(0xb, 1, 3), [4, 12, 513, 3]);
        assert_eq!(profile.leaf(0x16, 0, 0), [2900, 4300, 100, 0]);
        assert_eq!(profile.leaf(0xd, 0, 0), [7, 832, 832, 0]);
        for leaf in [2, 0x17, 0x40000000, 0x80000009, u32::MAX] {
            assert_eq!(profile.leaf(leaf, 0, 0), [0; 4]);
        }
        assert_eq!(profile.leaf(7, 1, 0), [0; 4]);
        assert_eq!(profile.leaf(7, 0, 0)[1] & 2, 2); // IA32_TSC_ADJUST is modeled.
        assert_eq!(profile.leaf(4, 4, 0), [0; 4]);
        let brand: Vec<_> = (0x80000002..=0x80000004)
            .flat_map(|leaf| profile.leaf(leaf, 0, 0))
            .flat_map(u32::to_le_bytes)
            .collect();
        assert_eq!(String::from_utf8(brand).unwrap().trim_end(), profile.brand);
        for index in 0..4 {
            let leaf = profile.leaf(4, index, 0);
            let size = ((leaf[1] >> 22) + 1) * ((leaf[1] & 4095) + 1) * (leaf[2] + 1);
            assert_eq!(size, [32768, 32768, 262144, 12582912][index as usize]);
        }
    }
    #[test]
    fn invalid_personas_are_rejected() {
        let mut profile = CpuProfile {
            cores: 0,
            ..CpuProfile::default()
        };
        assert!(profile.validate().is_err());
        profile.cores = 32;
        profile.threads_per_core = 2;
        assert_eq!(profile.leaf(0xb, 1, 0)[1], 64);
        profile.brand = "x".repeat(49);
        assert!(profile.validate().is_err());
        profile.brand = "nonascii:é".into();
        assert!(profile.validate().is_err());
        profile.brand = "test".into();
        profile.max_mhz = 100;
        assert!(profile.validate().is_err());
    }
    #[test]
    fn explicit_host_observations_override_only_matching_leaf_and_keep_processor_identity() {
        let mut profile = CpuProfile {
            cpuid_overrides: vec![CpuidOverride {
                function: 1,
                subleaf: 0,
                eax: 0x0008_06c2,
                ebx: 0x0010_0800,
                ecx: 0xfffa_f38f,
                edx: 0xbfeb_fbff,
            }],
            ..CpuProfile::default()
        };
        profile.validate().unwrap();
        assert_eq!(
            profile.leaf(1, 0, 3),
            [0x0008_06c2, 0x0310_0800, 0xfffa_f38f, 0xbfeb_fbff]
        );
        assert_eq!(profile.leaf(0, 0, 0), CpuProfile::default().leaf(0, 0, 0));
        profile.cpuid_overrides.push(profile.cpuid_overrides[0].clone());
        assert!(profile.validate().is_err());
    }
}
