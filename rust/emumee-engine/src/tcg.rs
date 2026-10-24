//! Fixed Unicorn JIT buffer for bounded submitted kernel-driver execution.
//! The installed 2.1.5 Rust wrapper lacks this control, so mirror its local
//! `uc_ctl_set/get_tcg_buffer_size` macros with exact `uint32_t` varargs.
use crate::Trace;
use anyhow::{Result, ensure};
use unicorn_engine::{
    Unicorn,
    unicorn_const::{ControlType, uc_ctl, uc_error},
};

pub(crate) const SUBMITTED_DRIVER_BUFFER_BYTES: u32 = 128 * 1024 * 1024;

pub(crate) fn configure_submitted_driver(engine: &mut Unicorn<Trace>) -> Result<u32> {
    let requested = SUBMITTED_DRIVER_BUFFER_BYTES;
    let write = ControlType(ControlType::TCG_BUFFER_SIZE.0 | ControlType::IO_WRITE.0);
    // SAFETY: local Unicorn 2.1.5 declares WRITE args as `(uint32_t)`;
    // `get_handle()` belongs to this live Unicorn instance.
    let error = unsafe { uc_ctl(engine.get_handle(), write, requested) };
    ensure!(
        error == uc_error::OK,
        "Unicorn TCG buffer set failed: {error:?}"
    );

    let mut actual = 0u32;
    let read = ControlType(ControlType::TCG_BUFFER_SIZE.0 | ControlType::IO_READ.0);
    // SAFETY: local Unicorn 2.1.5 declares READ args as `(uint32_t*)`.
    // The pointer remains valid for this synchronous call.
    let error = unsafe { uc_ctl(engine.get_handle(), read, &mut actual) };
    ensure!(
        error == uc_error::OK,
        "Unicorn TCG buffer read failed: {error:?}"
    );
    ensure!(
        actual == requested,
        "Unicorn adjusted submitted-driver TCG buffer outside fixed profile"
    );
    Ok(actual)
}
