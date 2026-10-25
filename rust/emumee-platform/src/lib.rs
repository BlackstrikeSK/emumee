//! Host worker boundary; guest execution models do not use these host APIs.
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod windows;
