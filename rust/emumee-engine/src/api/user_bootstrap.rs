use super::*;
use emumee_core::{
    persona::{Directory, Encoding, MAX_ENV_BYTES},
    virtual_memory as vm,
};
use unicorn_engine::unicorn_const::HookType;

const OWNER: u64 = 1024;
const PEB: u64 = 0x2000;
const PARAMETERS: u64 = 0x3000;
const GDT: u64 = 0x4000;
const IMAGE: u64 = 0x5000;
const DIRECTORY: u64 = 0x15000;
const ENVIRONMENT: u64 = 0x25000;
const TEXT_CAPACITY: usize = 0x10000;
const SIZE: u64 = ENVIRONMENT + MAX_ENV_BYTES as u64;

pub(crate) struct State {
    base: u64,
    active_teb: u64,
    wide: bool,
    last_error: u32,
    guest_error_dirty: bool,
    command_line: u64,
    image_base: u64,
    stack_limit: u64,
    stack_base: u64,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub teb: u64,
    pub peb: u64,
    pub process_parameters: u64,
    pub command_line: u64,
    pub environment: u64,
    pub image_base: u64,
    pub stack_limit: u64,
    pub stack_base: u64,
    pub process_id: u64,
    pub thread_id: u64,
    pub last_error: u32,
    pub mapped_bytes: u64,
    pub scope: &'static str,
}

impl State {
    fn error_address(&self) -> u64 {
        self.active_teb + if self.wide { 0x68 } else { 0x34 }
    }
}

fn put(engine: &mut Unicorn<Trace>, address: u64, value: u64, width: usize) -> Result<()> {
    crate::cpu::write(engine, address, &value.to_le_bytes()[..width])
}

fn string(engine: &mut Unicorn<Trace>, descriptor: u64, buffer: u64, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= 2 && bytes.len() <= TEXT_CAPACITY && bytes.len() % 2 == 0,
        "Bootstrap Unicode string exceeds descriptor bound"
    );
    let width = engine.get_data().architecture.width();
    put(engine, descriptor, (bytes.len() - 2) as u64, 2)?;
    put(
        engine,
        descriptor + 2,
        bytes.len().min(u16::MAX as usize - 1) as u64,
        2,
    )?;
    put(
        engine,
        descriptor + if width == 8 { 8 } else { 4 },
        buffer,
        width,
    )
}

pub(crate) fn refresh_process(engine: &mut Unicorn<Trace>) -> Result<()> {
    let Some(state) = &engine.get_data().apis.user_bootstrap else {
        return Ok(());
    };
    let (base, wide) = (state.base, state.wide);
    let model = &engine.get_data().apis.persona.model;
    let directory = model
        .directory(
            OWNER,
            Directory::Current,
            Encoding::Utf16,
            TEXT_CAPACITY as u32,
            true,
        )?
        .bytes
        .ok_or_else(|| anyhow::anyhow!("Bootstrap current directory absent"))?;
    let environment = model.environment_block(OWNER, Encoding::Utf16)?;
    ensure!(
        directory.len() <= TEXT_CAPACITY && environment.len() <= MAX_ENV_BYTES,
        "Bootstrap process text exceeds bound"
    );
    crate::cpu::write(engine, base + DIRECTORY, &directory)?;
    crate::cpu::write(engine, base + ENVIRONMENT, &environment)?;
    string(
        engine,
        base + PARAMETERS + if wide { 0x38 } else { 0x24 },
        base + DIRECTORY,
        &directory,
    )?;
    Ok(())
}

pub(crate) fn require_change(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    if let Some(state) = &engine.get_data().apis.user_bootstrap {
        let end = address
            .checked_add(size.max(1))
            .ok_or_else(|| anyhow::anyhow!("Bootstrap mapping range overflow"))?;
        ensure!(
            address >= state.base + SIZE || end <= state.base,
            "Mapping change overlaps owned user bootstrap"
        );
    }
    Ok(())
}

pub(crate) fn before_instruction(engine: &mut Unicorn<Trace>) -> Result<()> {
    let Some(state) = &engine.get_data().apis.user_bootstrap else {
        return Ok(());
    };
    let (address, dirty, previous) = (
        state.error_address(),
        state.guest_error_dirty,
        state.last_error,
    );
    let current = if dirty {
        let mut bytes = [0; 4];
        uc(engine.mem_read(address, &mut bytes))?;
        u32::from_le_bytes(bytes)
    } else {
        engine.get_data().apis.last_error
    };
    if dirty {
        engine.get_data_mut().apis.last_error = current;
    } else if current != previous {
        put(engine, address, current as u64, 4)?;
    }
    let state = engine.get_data_mut().apis.user_bootstrap.as_mut().unwrap();
    state.last_error = current;
    state.guest_error_dirty = false;
    Ok(())
}

pub(crate) fn model_write(engine: &mut Unicorn<Trace>, address: u64, size: usize) -> Result<()> {
    let Some(state) = &engine.get_data().apis.user_bootstrap else {
        return Ok(());
    };
    let error = state.error_address();
    if address < error + 4 && address.saturating_add(size as u64) > error {
        let mut bytes = [0; 4];
        uc(engine.mem_read(error, &mut bytes))?;
        let value = u32::from_le_bytes(bytes);
        engine.get_data_mut().apis.last_error = value;
        let state = engine.get_data_mut().apis.user_bootstrap.as_mut().unwrap();
        state.last_error = value;
        state.guest_error_dirty = false;
    }
    Ok(())
}

pub(crate) fn initialize(
    engine: &mut Unicorn<Trace>,
    image_base: u64,
    stack: u64,
    stack_size: u64,
) -> Result<()> {
    ensure!(
        !engine.get_data().apis.kernel_mode && engine.get_data().apis.user_bootstrap.is_none(),
        "User bootstrap requires a new user process"
    );
    let wide = engine.get_data().architecture == Architecture::X64;
    let width = engine.get_data().architecture.width();
    let command_line = persona::stable_command_line(engine, Encoding::Utf16)?;
    let desktop =
        super::user_runtime::stable_string(engine, super::user_runtime::DESKTOP_NAME, true)?;
    let desktop_bytes = Encoding::Utf16.encode(super::user_runtime::DESKTOP_NAME, true);
    ensure!(
        command_line != 0,
        "Bootstrap command-line allocation refused"
    );
    let model = &engine.get_data().apis.persona.model;
    let image = Encoding::Utf16.encode(&model.argv(OWNER)?[0], true);
    let command = model.command_line(OWNER, Encoding::Utf16)?;
    ensure!(
        image.len() <= TEXT_CAPACITY && command.len() <= TEXT_CAPACITY,
        "Bootstrap process strings exceed bound"
    );
    let handles = engine
        .get_data()
        .apis
        .crt_stdio
        .model
        .standard_handles(OWNER)?;
    let state = &engine.get_data().apis;
    let plan = state
        .allocations
        .allocate(&state.memory, 0, SIZE, vm::RESERVE | vm::COMMIT, 4)?;
    let base = allocation::apply(engine, plan)?;
    let stack_base = stack
        .checked_add(stack_size)
        .ok_or_else(|| anyhow::anyhow!("Bootstrap stack overflow"))?;
    let last_error = engine.get_data().apis.last_error;
    engine.get_data_mut().apis.user_bootstrap = Some(State {
        base,
        active_teb: base,
        wide,
        last_error,
        guest_error_dirty: false,
        command_line,
        image_base,
        stack_limit: stack,
        stack_base,
    });
    for (offset, value) in [
        (0, if wide { u64::MAX } else { u32::MAX as u64 }),
        (width as u64, stack_base),
        (2 * width as u64, stack),
        (if wide { 0x30 } else { 0x18 }, base),
        (if wide { 0x40 } else { 0x20 }, OWNER),
        (
            if wide { 0x48 } else { 0x24 },
            crate::threads::current_id(engine),
        ),
        (if wide { 0x60 } else { 0x30 }, base + PEB),
    ] {
        put(engine, base + offset, value, width)?;
    }
    put(
        engine,
        base + if wide { 0x68 } else { 0x34 },
        last_error as u64,
        4,
    )?;
    put(
        engine,
        base + PEB + if wide { 0x10 } else { 8 },
        image_base,
        width,
    )?;
    put(
        engine,
        base + PEB + if wide { 0x20 } else { 0x10 },
        base + PARAMETERS,
        width,
    )?;
    let processors = engine
        .get_data()
        .apis
        .persona
        .model
        .config()
        .logical_processors;
    let build = engine.get_data().machine.windows_build();
    for (offset, value, size) in [
        (if wide { 0xb8 } else { 0x64 }, processors as u64, 4),
        (if wide { 0x118 } else { 0xa4 }, 10, 4),
        (if wide { 0x11c } else { 0xa8 }, 0, 4),
        (if wide { 0x120 } else { 0xac }, build as u64, 2),
        (if wide { 0x124 } else { 0xb0 }, 2, 4),
    ] {
        put(engine, base + PEB + offset, value, size)?;
    }
    for (offset, value) in [(0, 0x1000), (4, if wide { 0xf0 } else { 0x90 }), (8, 1)] {
        put(engine, base + PARAMETERS + offset, value, 4)?;
    }
    for (index, handle) in handles.into_iter().enumerate() {
        put(
            engine,
            base + PARAMETERS + if wide { 0x20 } else { 0x18 } + index as u64 * width as u64,
            handle,
            width,
        )?;
    }
    crate::cpu::write(engine, base + IMAGE, &image)?;
    string(
        engine,
        base + PARAMETERS + if wide { 0x60 } else { 0x38 },
        base + IMAGE,
        &image,
    )?;
    string(
        engine,
        base + PARAMETERS + if wide { 0x70 } else { 0x40 },
        command_line,
        &command,
    )?;
    string(
        engine,
        base + PARAMETERS + if wide { 0xc0 } else { 0x78 },
        desktop,
        &desktop_bytes,
    )?;
    put(
        engine,
        base + PARAMETERS + if wide { 0x80 } else { 0x48 },
        base + ENVIRONMENT,
        width,
    )?;
    refresh_process(engine)?;
    if wide {
        uc(engine.reg_write(RegisterX86::GS_BASE, base))?;
    } else {
        let tables = base + GDT;
        put(engine, tables + 8, 0x00cf9a000000ffff, 8)?;
        put(engine, tables + 16, 0x00cf92000000ffff, 8)?;
        let descriptor = 0x1fffu64
            | ((base & 0xffff) << 16)
            | (((base >> 16) & 255) << 32)
            | (0x92 << 40)
            | (0x4 << 52)
            | (((base >> 24) & 255) << 56);
        put(engine, tables + 0x30, descriptor, 8)?;
        crate::kernel_cpu::table(engine, RegisterX86::GDTR, tables, 0x3f)?;
        uc(engine.reg_write(RegisterX86::CS, 8))?;
        for register in [RegisterX86::SS, RegisterX86::DS, RegisterX86::ES] {
            uc(engine.reg_write(register, 16))?;
        }
        uc(engine.reg_write(RegisterX86::FS, 0x30))?;
    }
    let state = &engine.get_data().apis;
    let plan = state
        .allocations
        .protect(&state.memory, base + GDT, 4096, 2)?;
    allocation::apply(engine, plan)?;
    let error_address = base + if wide { 0x68 } else { 0x34 };
    uc(engine.add_mem_hook(
        HookType::MEM_WRITE,
        base,
        base + PEB - 1,
        move |engine, _, address, size, _| {
            if address < error_address + 4
                && address.saturating_add(size as u64) > error_address
                && let Some(state) = engine.get_data_mut().apis.user_bootstrap.as_mut()
                && state.active_teb == base
            {
                state.guest_error_dirty = true;
            }
            true
        },
    ))?;
    Ok(())
}

pub(crate) fn active_teb(engine: &Unicorn<Trace>) -> Option<u64> {
    engine
        .get_data()
        .apis
        .user_bootstrap
        .as_ref()
        .map(|state| state.active_teb)
}

pub(crate) fn initialize_thread(
    engine: &mut Unicorn<Trace>,
    teb: u64,
    stack: u64,
    size: u64,
    thread: u64,
) -> Result<()> {
    let root = engine
        .get_data()
        .apis
        .user_bootstrap
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Thread process bootstrap is absent"))?
        .base;
    let width = engine.get_data().architecture.width();
    let wide = width == 8;
    for (offset, value) in [
        (0, if wide { u64::MAX } else { u32::MAX as u64 }),
        (width as u64, stack + size),
        (2 * width as u64, stack),
        (if wide { 0x30 } else { 0x18 }, teb),
        (if wide { 0x40 } else { 0x20 }, OWNER),
        (if wide { 0x48 } else { 0x24 }, thread),
        (if wide { 0x60 } else { 0x30 }, root + PEB),
    ] {
        put(engine, teb + offset, value, width)?;
    }
    let error_address = teb + if wide { 0x68 } else { 0x34 };
    uc(engine.add_mem_hook(
        HookType::MEM_WRITE,
        teb,
        teb + 8191,
        move |engine, _, address, size, _| {
            if address < error_address + 4
                && address.saturating_add(size as u64) > error_address
                && let Some(state) = engine.get_data_mut().apis.user_bootstrap.as_mut()
                && state.active_teb == teb
            {
                state.guest_error_dirty = true;
            }
            true
        },
    ))?;
    Ok(())
}

pub(crate) fn activate_thread(engine: &mut Unicorn<Trace>, teb: u64) -> Result<()> {
    before_instruction(engine)?;
    let state = engine
        .get_data()
        .apis
        .user_bootstrap
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Thread process bootstrap is absent"))?;
    let (wide, tables) = (state.wide, state.base + GDT);
    let mut error = [0; 4];
    uc(engine.mem_read(teb + if wide { 0x68 } else { 0x34 }, &mut error))?;
    if wide {
        uc(engine.reg_write(RegisterX86::GS_BASE, teb))?;
    } else {
        let descriptor = 0x1fffu64
            | ((teb & 0xffff) << 16)
            | (((teb >> 16) & 255) << 32)
            | (0x92 << 40)
            | (0x4 << 52)
            | (((teb >> 24) & 255) << 56);
        put(engine, tables + 0x30, descriptor, 8)?;
        uc(engine.reg_write(RegisterX86::FS, 0))?;
        uc(engine.reg_write(RegisterX86::FS, 0x30))?;
    }
    let error = u32::from_le_bytes(error);
    engine.get_data_mut().apis.last_error = error;
    let state = engine.get_data_mut().apis.user_bootstrap.as_mut().unwrap();
    state.active_teb = teb;
    state.last_error = error;
    state.guest_error_dirty = false;
    Ok(())
}

pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = engine.get_data().apis.user_bootstrap.as_ref()?;
    Some(Report {
        teb: state.base,
        peb: state.base + PEB,
        process_parameters: state.base + PARAMETERS,
        command_line: state.command_line,
        environment: state.base + ENVIRONMENT,
        image_base: state.image_base,
        stack_limit: state.stack_limit,
        stack_base: state.stack_base,
        process_id: OWNER,
        thread_id: crate::threads::current_id(engine),
        last_error: engine.get_data().apis.last_error,
        mapped_bytes: SIZE,
        scope: "Owned submitted-user root bootstrap; existing persona/VFS/stdio authority, direct FS/GS TIB/PEB/process-parameter projection and shared LastError. Loader lists, static TLS and thread lifecycle are separate M3/M4 obligations.",
    })
}
