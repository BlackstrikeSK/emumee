//! M7 guest control families for the network, COM, cryptography, security and
//! resource API partitions.
//!
//! As with M6, each control is a generated x86/x64 caller that reaches the
//! modeled exports through a real import table and decides its own outcome:
//! every expected value is compared by guest instructions, so a wrong answer
//! raises a breakpoint inside the guest rather than being reported back for a
//! host assertion. Controls are emitted as contained fixtures so the packaged
//! worker replays the same bytes through the public CLI.
use super::*;
use crate::m6_tests::{run, succeeded};

mod com;
mod crypto;
mod network;
mod path;
mod resources;
mod security;
mod sockets;
