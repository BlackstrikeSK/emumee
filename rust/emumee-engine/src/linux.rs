//! Independent, bounded Linux x86-64 guest profile. Guest syscalls never call host APIs.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use emumee_core::elf::StaticLoadPlan;
use serde::Serialize;
use sha2::{Digest, Sha256};
use unicorn_engine::{
    RegisterX86, Unicorn, X86Insn,
    unicorn_const::{Arch, Mode, Prot},
};

use crate::uc;

const PAGE: u64 = 4096;
const STACK_BASE: u64 = 0x0000_7fff_0000_0000;
const STACK_SIZE: u64 = 1024 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_WRITE: usize = 64 * 1024;
const MAX_SYSCALLS: usize = 1024;
const MAX_INSTRUCTIONS: u64 = 1_000_000;
const MAX_TIMEOUT_US: u64 = 30_000_000;

#[derive(Clone, Debug, Serialize)]
pub struct SyscallEvent {
    pub number: u64,
    pub arguments: [u64; 6],
    pub result: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct Execution {
    pub schema: u32,
    pub format: &'static str,
    pub architecture: &'static str,
    pub input_sha256: String,
    pub entry: u64,
    pub instructions: u64,
    pub initial_stack_pointer: u64,
    pub completion_reason: &'static str,
    pub exit_code: Option<u8>,
    pub unsupported_syscall: Option<u64>,
    pub cpu_error: Option<String>,
    pub syscalls: Vec<SyscallEvent>,
    pub stdout_base64: String,
    pub stderr_base64: String,
}

enum Stop {
    Exit(u8),
    Unsupported(u64),
    OutputLimit,
    MemoryFault,
    HookFailure,
    SyscallLimit,
}

#[derive(Default)]
struct State {
    instructions: u64,
    syscalls: Vec<SyscallEvent>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stop: Option<Stop>,
}

fn stop(engine: &mut Unicorn<State>, reason: Stop) {
    engine.get_data_mut().stop = Some(reason);
    let _ = engine.emu_stop();
}

fn syscall(engine: &mut Unicorn<State>) {
    let registers = [
        RegisterX86::RAX,
        RegisterX86::RDI,
        RegisterX86::RSI,
        RegisterX86::RDX,
        RegisterX86::R10,
        RegisterX86::R8,
        RegisterX86::R9,
    ];
    let mut values = [0u64; 7];
    for (slot, register) in values.iter_mut().zip(registers) {
        match engine.reg_read(register) {
            Ok(value) => *slot = value,
            Err(_) => {
                stop(engine, Stop::HookFailure);
                return;
            }
        }
    }
    let number = values[0];
    let arguments: [u64; 6] = values[1..].try_into().unwrap();
    if engine.get_data().syscalls.len() >= MAX_SYSCALLS {
        stop(engine, Stop::SyscallLimit);
        return;
    }
    let mut result = None;
    let mut reason = None;
    match number {
        0 => {
            // Closed stdin. Other descriptors do not exist in this profile.
            result = Some(if arguments[0] == 0 { 0 } else { -9 });
        }
        1 => {
            let fd = arguments[0];
            if fd != 1 && fd != 2 {
                result = Some(-9);
            } else if arguments[2] > MAX_WRITE as u64
                || engine.get_data().stdout.len() + engine.get_data().stderr.len()
                    > MAX_OUTPUT.saturating_sub(arguments[2] as usize)
            {
                reason = Some(Stop::OutputLimit);
            } else {
                match engine.mem_read_as_vec(arguments[1], arguments[2] as usize) {
                    Ok(bytes) => {
                        let state = engine.get_data_mut();
                        if fd == 1 {
                            state.stdout.extend_from_slice(&bytes);
                        } else {
                            state.stderr.extend_from_slice(&bytes);
                        }
                        result = Some(bytes.len() as i64);
                    }
                    Err(_) => reason = Some(Stop::MemoryFault),
                }
            }
        }
        39 => result = Some(1000), // getpid: deterministic guest identity.
        60 | 231 => reason = Some(Stop::Exit(arguments[0] as u8)),
        _ => reason = Some(Stop::Unsupported(number)),
    }
    engine.get_data_mut().syscalls.push(SyscallEvent {
        number,
        arguments,
        result,
    });
    if let Some(reason) = reason {
        stop(engine, reason);
    } else if uc(engine.reg_write(RegisterX86::RAX, result.unwrap() as u64)).is_err() {
        stop(engine, Stop::HookFailure);
    }
}

fn stack_bytes(engine: &mut Unicorn<State>, cursor: &mut u64, bytes: &[u8]) -> Result<u64> {
    *cursor = cursor
        .checked_sub(bytes.len() as u64)
        .context("Guest stack underflow")?;
    ensure!(*cursor >= STACK_BASE, "Guest stack data exceeds bound");
    uc(engine.mem_write(*cursor, bytes))?;
    Ok(*cursor)
}

fn map_stack(engine: &mut Unicorn<State>, plan: &StaticLoadPlan, input: &[u8]) -> Result<u64> {
    uc(engine.mem_map(STACK_BASE, STACK_SIZE, Prot::READ | Prot::WRITE))?;
    let mut cursor = STACK_BASE + STACK_SIZE;
    let arg0 = stack_bytes(engine, &mut cursor, b"/sample\0")?;
    let platform = stack_bytes(engine, &mut cursor, b"x86_64\0")?;
    let digest = Sha256::digest(input);
    let random = stack_bytes(engine, &mut cursor, &digest[..16])?;
    let words: Vec<u64> = vec![
        1,
        arg0,
        0,
        0, // argc, argv[0], argv terminator, envp terminator
        3,
        plan.program_header_address, // AT_PHDR
        4,
        plan.program_header_entry_size as u64, // AT_PHENT
        5,
        plan.program_header_count as u64, // AT_PHNUM
        6,
        PAGE, // AT_PAGESZ
        9,
        plan.entry, // AT_ENTRY
        11,
        1000, // AT_UID
        12,
        1000, // AT_EUID
        13,
        1000, // AT_GID
        14,
        1000, // AT_EGID
        23,
        0, // AT_SECURE
        25,
        random, // AT_RANDOM
        15,
        platform, // AT_PLATFORM
        31,
        arg0, // AT_EXECFN
        0,
        0, // AT_NULL
    ];
    let stack_pointer = cursor
        .checked_sub((words.len() * 8) as u64)
        .context("Guest stack words overflow")?
        & !15;
    ensure!(
        stack_pointer >= STACK_BASE,
        "Guest stack words exceed bound"
    );
    for (index, word) in words.iter().enumerate() {
        uc(engine.mem_write(stack_pointer + index as u64 * 8, &word.to_le_bytes()))?;
    }
    Ok(stack_pointer)
}

fn map_image(engine: &mut Unicorn<State>, plan: &StaticLoadPlan, input: &[u8]) -> Result<()> {
    for segment in &plan.segments {
        uc(engine.mem_map(
            segment.page_start,
            segment.page_size,
            Prot::READ | Prot::WRITE,
        ))?;
        let start = usize::try_from(segment.file_offset).context("File offset overflow")?;
        let end = start
            .checked_add(usize::try_from(segment.file_size).context("File size overflow")?)
            .context("File range overflow")?;
        uc(engine.mem_write(
            segment.virtual_address,
            input.get(start..end).context("Load bytes missing")?,
        ))?;
        let mut protection = Prot::NONE;
        if segment.flags & 4 != 0 {
            protection |= Prot::READ;
        }
        if segment.flags & 2 != 0 {
            protection |= Prot::WRITE;
        }
        if segment.flags & 1 != 0 {
            protection |= Prot::EXEC;
        }
        uc(engine.mem_protect(segment.page_start, segment.page_size, protection))?;
    }
    Ok(())
}

/// Execute only the closed static x86-64 profile. Callers handling untrusted
/// samples must use a separately verified, restricted worker process.
pub fn run_static(input: &[u8], max_instructions: u64, timeout_us: u64) -> Result<Execution> {
    ensure!(
        (1..=MAX_INSTRUCTIONS).contains(&max_instructions)
            && (1..=MAX_TIMEOUT_US).contains(&timeout_us),
        "Linux guest budget outside closed profile"
    );
    let plan = StaticLoadPlan::parse(input)?;
    // The pinned Windows backend has process-wide mutable code-cache hooks.
    #[cfg(windows)]
    let _lease = crate::NATIVE_INSTANCE
        .lock()
        .map_err(|_| anyhow::anyhow!("Native engine lifetime guard is poisoned"))?;
    let mut engine = uc(Unicorn::new_with_data(
        Arch::X86,
        Mode::MODE_64,
        State::default(),
    ))?;
    map_image(&mut engine, &plan, input)?;
    let stack_pointer = map_stack(&mut engine, &plan, input)?;
    uc(engine.reg_write(RegisterX86::RSP, stack_pointer))?;
    uc(engine.reg_write(RegisterX86::RBP, 0))?;
    uc(engine.reg_write(RegisterX86::RDX, 0))?;
    uc(engine.reg_write(RegisterX86::EFLAGS, 2))?;
    uc(engine.add_code_hook(1, 0, |engine, _, _| {
        engine.get_data_mut().instructions += 1;
    }))?;
    uc(engine.add_insn_sys_hook(X86Insn::SYSCALL, 1, 0, syscall))?;
    let emulation = engine.emu_start(plan.entry, 0, timeout_us, max_instructions as usize);
    let state = engine.get_data();
    let (completion_reason, exit_code, unsupported_syscall) = match state.stop {
        Some(Stop::Exit(code)) => ("exit", Some(code), None),
        Some(Stop::Unsupported(number)) => ("unsupported_syscall", None, Some(number)),
        Some(Stop::OutputLimit) => ("output_limit", None, None),
        Some(Stop::MemoryFault) => ("guest_memory_fault", None, None),
        Some(Stop::HookFailure) => ("hook_failure", None, None),
        Some(Stop::SyscallLimit) => ("syscall_limit", None, None),
        None if emulation.is_err() => ("cpu_fault", None, None),
        None if state.instructions >= max_instructions => ("instruction_limit", None, None),
        None => ("timeout", None, None),
    };
    Ok(Execution {
        schema: 1,
        format: "elf",
        architecture: "x64",
        input_sha256: plan.sha256,
        entry: plan.entry,
        instructions: state.instructions,
        initial_stack_pointer: stack_pointer,
        completion_reason,
        exit_code,
        unsupported_syscall,
        cpu_error: emulation.err().map(|error| format!("{error:?}")),
        syscalls: state.syscalls.clone(),
        stdout_base64: STANDARD.encode(&state.stdout),
        stderr_base64: STANDARD.encode(&state.stderr),
    })
}

#[cfg(test)]
mod tests;
