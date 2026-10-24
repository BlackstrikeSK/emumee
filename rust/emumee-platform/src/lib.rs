//! Host worker boundary; guest execution models do not use these host APIs.
#[cfg(windows)]
pub mod windows;
