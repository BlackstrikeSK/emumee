//! Finite generated IL string-event fixtures, never host CLR execution.
use crate::pe::Architecture;
use serde::{Deserialize, Serialize};
pub const PREFIX: &str = "http://";
pub const SUFFIX: &str = "managed.example/ 😀 198.51.100.17";
pub const SURROGATE_PREFIX: &str = "http://surrogate.example/";
pub const FAILURE: &str = "http://argument.example/";
pub const NULLABLE: &str = "http://nullable.example/";
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    Events,
    Disabled,
    Budget,
    Surrogate,
    FrameworkFailure,
    Null,
}
impl Case {
    pub const ALL: [Self; 6] = [
        Self::Events,
        Self::Disabled,
        Self::Budget,
        Self::Surrogate,
        Self::FrameworkFailure,
        Self::Null,
    ];
    pub fn enabled(self) -> bool {
        self != Self::Disabled
    }
    pub fn budget(self) -> u64 {
        if self == Self::Budget { 2 } else { 1000 }
    }
    pub fn input(self, architecture: Architecture) -> Vec<u8> {
        crate::fixtures::managed_indicator_probe(architecture, self)
    }
}
