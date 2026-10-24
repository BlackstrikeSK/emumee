//! Deterministic kernel processor identity and documented user address limits.
//! No host topology, native API, object addresses or private Windows data.
use crate::{cpu::CpuProfile, pe::Architecture};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Kernel environment: {0}")]
pub struct EnvironmentError(pub &'static str);

#[derive(Clone, Debug, Serialize)]
pub struct Environment {
    pub logical_processors: u32,
    pub current_processor: u32,
    pub windows_build: u32,
    pub highest_user_address: u64,
    pub user_probe_address: u64,
    pub debugger_enabled: bool,
    pub debugger_present: bool,
    architecture: Architecture,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Global {
    NumberProcessors,
    HighestUserAddress,
    UserProbeAddress,
    DebuggerEnabled,
    DebuggerNotPresent,
}
impl Global {
    pub const ALL: [Self; 5] = [
        Self::NumberProcessors,
        Self::HighestUserAddress,
        Self::UserProbeAddress,
        Self::DebuggerEnabled,
        Self::DebuggerNotPresent,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::NumberProcessors => "KeNumberProcessors",
            Self::HighestUserAddress => "MmHighestUserAddress",
            Self::UserProbeAddress => "MmUserProbeAddress",
            Self::DebuggerEnabled => "KdDebuggerEnabled",
            Self::DebuggerNotPresent => "KdDebuggerNotPresent",
        }
    }
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|global| global.name() == name)
    }
}
impl Environment {
    pub fn new(
        architecture: Architecture,
        profile: &CpuProfile,
        windows_build: u32,
        current_processor: u32,
    ) -> Result<Self, EnvironmentError> {
        profile
            .validate()
            .map_err(|_| EnvironmentError("invalid configured CPU profile"))?;
        let logical_processors = profile
            .cores
            .checked_mul(profile.threads_per_core)
            .ok_or(EnvironmentError("configured topology overflow"))?;
        if current_processor >= logical_processors || windows_build == 0 {
            return Err(EnvironmentError(
                "invalid current processor or Windows build",
            ));
        }
        let top = match architecture {
            Architecture::X86 => 1u64 << 31,
            Architecture::X64 if windows_build >= 9600 => 1u64 << 47,
            Architecture::X64 => 1u64 << 43,
        };
        Ok(Self {
            logical_processors,
            current_processor,
            windows_build,
            highest_user_address: top - 0x10001,
            user_probe_address: top - 0x10000,
            debugger_enabled: false,
            debugger_present: false,
            architecture,
        })
    }
    /// Boot policy controls enablement. No attached debugger transport exists
    /// in this model; enabling debugging does not fabricate a connection.
    pub fn with_boot_debug(mut self, enabled: bool) -> Self {
        self.debugger_enabled = enabled;
        self
    }
    /// GROUP_NUMBER is USHORT even in a pointer-width argument slot.
    pub fn active_processor_count_ex(&self, group: u64) -> u32 {
        let group = group as u16;
        if group == u16::MAX {
            return self.logical_processors;
        }
        self.logical_processors
            .saturating_sub(u32::from(group) * 64)
            .min(64)
    }
    pub fn current_processor_number(&self) -> u32 {
        self.current_processor % 64
    }
    /// Full PROCESSOR_NUMBER output. The adapter checks all four writable
    /// bytes before applying this single effect; a NULL output is optional.
    pub fn processor_number(&self) -> [u8; 4] {
        let group = (self.current_processor / 64) as u16;
        let [lo, hi] = group.to_le_bytes();
        [lo, hi, self.current_processor_number() as u8, 0]
    }
    pub fn global_bytes(&self, global: Global) -> Vec<u8> {
        match global {
            Global::NumberProcessors => vec![self.logical_processors.min(64) as u8],
            Global::HighestUserAddress => {
                self.highest_user_address.to_le_bytes()[..self.architecture.width()].to_vec()
            }
            Global::UserProbeAddress => {
                self.user_probe_address.to_le_bytes()[..self.architecture.width()].to_vec()
            }
            Global::DebuggerEnabled => vec![u8::from(self.debugger_enabled)],
            Global::DebuggerNotPresent => vec![u8::from(!self.debugger_present)],
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn debugger_enablement_is_a_byte_and_does_not_imply_an_attached_debugger() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for enabled in [false, true] {
                let model = Environment::new(architecture, &CpuProfile::default(), 26200, 0)
                    .unwrap()
                    .with_boot_debug(enabled);
                assert_eq!(
                    model.global_bytes(Global::DebuggerEnabled),
                    [u8::from(enabled)]
                );
                assert_eq!(model.global_bytes(Global::DebuggerNotPresent), [1]);
                assert!(!model.debugger_present);
                assert_eq!(
                    Global::from_name("KdDebuggerEnabled"),
                    Some(Global::DebuggerEnabled)
                );
            }
        }
    }
    #[test]
    fn configured_topology_group_ushort_and_processor_number_agree() {
        let mut profile = CpuProfile {
            cores: 3,
            threads_per_core: 2,
            ..CpuProfile::default()
        };
        for architecture in [Architecture::X86, Architecture::X64] {
            let model = Environment::new(architecture, &profile, 22631, 5).unwrap();
            assert_eq!(model.active_processor_count_ex(0), 6);
            assert_eq!(model.active_processor_count_ex(1), 0);
            assert_eq!(model.active_processor_count_ex(65534), 0);
            assert_eq!(model.active_processor_count_ex(65535), 6);
            assert_eq!(model.active_processor_count_ex(0x1_0000), 6);
            assert_eq!(model.active_processor_count_ex(u64::MAX), 6);
            assert_eq!(model.current_processor_number(), 5);
            assert_eq!(model.processor_number(), [0, 0, 5, 0]);
            assert_eq!(model.global_bytes(Global::NumberProcessors), [6]);
        }
        profile.cores = 32;
        profile.threads_per_core = 2;
        assert_eq!(
            Environment::new(Architecture::X64, &profile, 22631, 63)
                .unwrap()
                .processor_number(),
            [0, 0, 63, 0]
        );
        assert!(Environment::new(Architecture::X64, &profile, 22631, 64).is_err());
        profile.cores = u32::MAX;
        assert!(Environment::new(Architecture::X64, &profile, 22631, 0).is_err());
    }
    #[test]
    fn pointer_sized_limits_preserve_legacy_build_boundary_without_host_queries() {
        for (architecture, build, highest) in [
            (Architecture::X64, 22631, 0x7fff_fffe_ffff),
            (Architecture::X64, 7601, 0x7ff_fffe_ffff),
            (Architecture::X86, 22631, 0x7ffe_ffff),
        ] {
            let model = Environment::new(architecture, &CpuProfile::default(), build, 0).unwrap();
            assert_eq!(model.highest_user_address, highest);
            assert_eq!(model.user_probe_address, highest + 1);
            assert_eq!(
                model.global_bytes(Global::HighestUserAddress),
                highest.to_le_bytes()[..architecture.width()]
            );
            assert_eq!(
                model.global_bytes(Global::UserProbeAddress).len(),
                architecture.width()
            );
        }
        assert!(Environment::new(Architecture::X64, &CpuProfile::default(), 0, 0).is_err());
    }
}
