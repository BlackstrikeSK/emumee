//! Independent, bounded Linux x86 guest profiles. Guest syscalls never call host APIs.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use emumee_core::elf::{
    Pie32LoadPlan, PieLoadPlan, RelativeRelocation, SharedLoadPlan, Static32LoadPlan,
    StaticLoadPlan, TlsBlock,
};
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
const STACK32_BASE: u64 = 0xbfe0_0000;
const TLS_TP: u64 = 0x0000_7ffe_1001_0000;
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
    pub unsupported_interrupt: Option<u32>,
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
    Interrupt(u32),
}

#[derive(Clone, Copy)]
enum GuestAbi {
    X64,
    X86,
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

fn syscall_for(engine: &mut Unicorn<State>, abi: GuestAbi) {
    let registers = match abi {
        GuestAbi::X64 => [
            RegisterX86::RAX,
            RegisterX86::RDI,
            RegisterX86::RSI,
            RegisterX86::RDX,
            RegisterX86::R10,
            RegisterX86::R8,
            RegisterX86::R9,
        ],
        GuestAbi::X86 => [
            RegisterX86::EAX,
            RegisterX86::EBX,
            RegisterX86::ECX,
            RegisterX86::EDX,
            RegisterX86::ESI,
            RegisterX86::EDI,
            RegisterX86::EBP,
        ],
    };
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
    let (read_number, write_number, getpid_number, exit_number, exit_group_number) = match abi {
        GuestAbi::X64 => (0, 1, 39, 60, 231),
        GuestAbi::X86 => (3, 4, 20, 1, 252),
    };
    match number {
        n if n == read_number => {
            // Closed stdin. Other descriptors do not exist in this profile.
            result = Some(if arguments[0] == 0 { 0 } else { -9 });
        }
        n if n == write_number => {
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
        n if n == getpid_number => result = Some(1000),
        n if n == exit_number || n == exit_group_number => {
            reason = Some(Stop::Exit(arguments[0] as u8))
        }
        _ => reason = Some(Stop::Unsupported(number)),
    }
    engine.get_data_mut().syscalls.push(SyscallEvent {
        number,
        arguments,
        result,
    });
    if let Some(reason) = reason {
        stop(engine, reason);
    } else if uc(engine.reg_write(registers[0], result.unwrap() as u64)).is_err() {
        stop(engine, Stop::HookFailure);
    }
}

fn syscall64(engine: &mut Unicorn<State>) {
    syscall_for(engine, GuestAbi::X64);
}

fn interrupt32(engine: &mut Unicorn<State>, interrupt: u32) {
    if interrupt == 0x80 {
        syscall_for(engine, GuestAbi::X86);
    } else {
        stop(engine, Stop::Interrupt(interrupt));
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

fn map_stack32(engine: &mut Unicorn<State>, plan: &StaticLoadPlan, input: &[u8]) -> Result<u64> {
    uc(engine.mem_map(STACK32_BASE, STACK_SIZE, Prot::READ | Prot::WRITE))?;
    let mut cursor = STACK32_BASE + STACK_SIZE;
    let arg0 = stack_bytes32(engine, &mut cursor, b"/sample\0")?;
    let platform = stack_bytes32(engine, &mut cursor, b"i686\0")?;
    let digest = Sha256::digest(input);
    let random = stack_bytes32(engine, &mut cursor, &digest[..16])?;
    let words = [
        1,
        arg0,
        0,
        0, // argc, argv[0], argv terminator, envp terminator
        3,
        u32::try_from(plan.program_header_address)?,
        4,
        plan.program_header_entry_size as u32,
        5,
        plan.program_header_count as u32,
        6,
        PAGE as u32,
        9,
        u32::try_from(plan.entry)?,
        11,
        1000,
        12,
        1000,
        13,
        1000,
        14,
        1000,
        23,
        0,
        25,
        random,
        15,
        platform,
        31,
        arg0,
        0,
        0,
    ];
    let stack_pointer = cursor
        .checked_sub((words.len() * 4) as u64)
        .context("i386 guest stack words overflow")?
        & !15;
    ensure!(
        stack_pointer >= STACK32_BASE,
        "i386 guest stack exceeds bound"
    );
    for (index, word) in words.iter().enumerate() {
        uc(engine.mem_write(stack_pointer + index as u64 * 4, &word.to_le_bytes()))?;
    }
    Ok(stack_pointer)
}

fn stack_bytes32(engine: &mut Unicorn<State>, cursor: &mut u64, bytes: &[u8]) -> Result<u32> {
    *cursor = cursor
        .checked_sub(bytes.len() as u64)
        .context("i386 stack underflow")?;
    ensure!(*cursor >= STACK32_BASE, "i386 stack data exceeds bound");
    uc(engine.mem_write(*cursor, bytes))?;
    Ok(u32::try_from(*cursor)?)
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
    let plan = StaticLoadPlan::parse(input)?;
    run_plan(
        input,
        &plan,
        &[],
        &[],
        &[],
        &[],
        GuestAbi::X64,
        max_instructions,
        timeout_us,
    )
}

pub fn run_pie(input: &[u8], max_instructions: u64, timeout_us: u64) -> Result<Execution> {
    let plan = PieLoadPlan::parse(input)?;
    run_plan(
        input,
        &plan.image,
        &[],
        &plan.relocations,
        &[],
        &[],
        GuestAbi::X64,
        max_instructions,
        timeout_us,
    )
}

pub fn run_static32(input: &[u8], max_instructions: u64, timeout_us: u64) -> Result<Execution> {
    let plan = Static32LoadPlan::parse(input)?;
    run_plan(
        input,
        &plan.image,
        &[],
        &[],
        &[],
        &[],
        GuestAbi::X86,
        max_instructions,
        timeout_us,
    )
}

pub fn run_pie32(input: &[u8], max_instructions: u64, timeout_us: u64) -> Result<Execution> {
    let plan = Pie32LoadPlan::parse(input)?;
    run_plan(
        input,
        &plan.image,
        &[],
        &plan.relocations,
        &[],
        &[],
        GuestAbi::X86,
        max_instructions,
        timeout_us,
    )
}

pub fn run_shared(
    input: &[u8],
    libraries: &[(&str, &[u8])],
    max_instructions: u64,
    timeout_us: u64,
) -> Result<Execution> {
    let plan = SharedLoadPlan::parse(input, libraries)?;
    let mut mapped = Vec::with_capacity(plan.libraries.len());
    for (name, object) in plan.library_names.iter().zip(&plan.libraries) {
        let (_, bytes) = libraries
            .iter()
            .find(|(candidate, _)| candidate == name)
            .context("Staged library disappeared")?;
        mapped.push((object, *bytes));
    }
    run_plan(
        input,
        &plan.executable,
        &mapped,
        &plan.relocations,
        &plan.relro,
        &plan.tls,
        GuestAbi::X64,
        max_instructions,
        timeout_us,
    )
}

// Keep validated image/library inputs and execution bounds explicit at this boundary.
#[allow(clippy::too_many_arguments)]
fn run_plan(
    input: &[u8],
    plan: &StaticLoadPlan,
    libraries: &[(&StaticLoadPlan, &[u8])],
    relocations: &[RelativeRelocation],
    relro: &[(u64, u64)],
    tls: &[(usize, TlsBlock)],
    abi: GuestAbi,
    max_instructions: u64,
    timeout_us: u64,
) -> Result<Execution> {
    ensure!(
        (1..=MAX_INSTRUCTIONS).contains(&max_instructions)
            && (1..=MAX_TIMEOUT_US).contains(&timeout_us),
        "Linux guest budget outside closed profile"
    );
    // The pinned Windows backend has process-wide mutable code-cache hooks.
    #[cfg(windows)]
    let _lease = crate::NATIVE_INSTANCE
        .lock()
        .map_err(|_| anyhow::anyhow!("Native engine lifetime guard is poisoned"))?;
    let mode = match abi {
        GuestAbi::X64 => Mode::MODE_64,
        GuestAbi::X86 => Mode::MODE_32,
    };
    let mut engine = uc(Unicorn::new_with_data(Arch::X86, mode, State::default()))?;
    map_image(&mut engine, plan, input)?;
    for (library, bytes) in libraries {
        map_image(&mut engine, library, bytes)?;
    }
    for relocation in relocations {
        match relocation.width {
            4 => uc(engine.mem_write(relocation.target, &(relocation.value as u32).to_le_bytes()))?,
            8 => uc(engine.mem_write(relocation.target, &relocation.value.to_le_bytes()))?,
            _ => anyhow::bail!("Unsupported relocation width"),
        }
    }
    for &(start, size) in relro {
        uc(engine.mem_protect(start, size, Prot::READ))?;
    }
    if !tls.is_empty() {
        uc(engine.mem_map(TLS_TP - 0x10000, 0x11000, Prot::READ | Prot::WRITE))?;
        uc(engine.mem_write(TLS_TP, &TLS_TP.to_le_bytes()))?;
        for (index, block) in tls {
            let bytes = if *index == 0 {
                input
            } else {
                libraries.get(*index - 1).context("TLS library missing")?.1
            };
            let start = usize::try_from(block.file_offset)?;
            let end = start
                .checked_add(usize::try_from(block.file_size)?)
                .context("TLS file range overflow")?;
            let address = TLS_TP
                .checked_add_signed(block.offset_from_tp)
                .context("TLS address overflow")?;
            uc(engine.mem_write(
                address,
                bytes.get(start..end).context("TLS template missing")?,
            ))?;
        }
        uc(engine.reg_write(RegisterX86::FS_BASE, TLS_TP))?;
    }
    let stack_pointer = match abi {
        GuestAbi::X64 => map_stack(&mut engine, plan, input)?,
        GuestAbi::X86 => map_stack32(&mut engine, plan, input)?,
    };
    match abi {
        GuestAbi::X64 => {
            uc(engine.reg_write(RegisterX86::RSP, stack_pointer))?;
            uc(engine.reg_write(RegisterX86::RBP, 0))?;
            uc(engine.reg_write(RegisterX86::RDX, 0))?;
        }
        GuestAbi::X86 => {
            uc(engine.reg_write(RegisterX86::ESP, stack_pointer))?;
            uc(engine.reg_write(RegisterX86::EBP, 0))?;
            uc(engine.reg_write(RegisterX86::EDX, 0))?;
        }
    }
    uc(engine.reg_write(RegisterX86::EFLAGS, 2))?;
    uc(engine.add_code_hook(1, 0, |engine, _, _| {
        engine.get_data_mut().instructions += 1;
    }))?;
    match abi {
        GuestAbi::X64 => {
            uc(engine.add_insn_sys_hook(X86Insn::SYSCALL, 1, 0, syscall64))?;
        }
        GuestAbi::X86 => {
            uc(engine.add_intr_hook(interrupt32))?;
        }
    }
    let emulation = engine.emu_start(plan.entry, 0, timeout_us, max_instructions as usize);
    let state = engine.get_data();
    let (completion_reason, exit_code, unsupported_syscall, unsupported_interrupt) = match state
        .stop
    {
        Some(Stop::Exit(code)) => ("exit", Some(code), None, None),
        Some(Stop::Unsupported(number)) => ("unsupported_syscall", None, Some(number), None),
        Some(Stop::Interrupt(number)) => ("unsupported_interrupt", None, None, Some(number)),
        Some(Stop::OutputLimit) => ("output_limit", None, None, None),
        Some(Stop::MemoryFault) => ("guest_memory_fault", None, None, None),
        Some(Stop::HookFailure) => ("hook_failure", None, None, None),
        Some(Stop::SyscallLimit) => ("syscall_limit", None, None, None),
        None if emulation.is_err() => ("cpu_fault", None, None, None),
        None if state.instructions >= max_instructions => ("instruction_limit", None, None, None),
        None => ("timeout", None, None, None),
    };
    Ok(Execution {
        schema: 1,
        format: "elf",
        architecture: match abi {
            GuestAbi::X64 => "x64",
            GuestAbi::X86 => "x86",
        },
        input_sha256: plan.sha256.clone(),
        entry: plan.entry,
        instructions: state.instructions,
        initial_stack_pointer: stack_pointer,
        completion_reason,
        exit_code,
        unsupported_syscall,
        unsupported_interrupt,
        cpu_error: emulation.err().map(|error| format!("{error:?}")),
        syscalls: state.syscalls.clone(),
        stdout_base64: STANDARD.encode(&state.stdout),
        stderr_base64: STANDARD.encode(&state.stderr),
    })
}

#[cfg(test)]
mod tests;
