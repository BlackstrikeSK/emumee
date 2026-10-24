//! Initial user persona/environment adapters. All text comes from supplied
//! guest state; no host environment or native Windows API is consulted.
use super::*;
#[path = "persona_blocks.rs"]
mod blocks;
pub use blocks::Report as EnvironmentBlockReport;
use emumee_core::{
    persona::{
        self, BufferPlan, Directory, Encoding, Persona, PersonaConfig, PersonaError, ProcessConfig,
    },
    virtual_memory as vm,
};
const OWNER: u64 = 1024;
#[derive(Clone, Copy)]
pub(super) enum Call {
    Variable(Encoding),
    Set(Encoding),
    Expand(Encoding),
    Directory(Directory, Encoding),
    Computer(Encoding),
    ComputerEx(Encoding),
    User(Encoding),
    CommandLine(Encoding),
    Blocks(blocks::Call),
}
#[derive(Clone, Debug)]
struct StableText {
    address: u64,
    size: u64,
    bytes: usize,
}
pub(crate) struct State {
    pub model: Persona,
    command_lines: BTreeMap<(u64, u8), StableText>,
    environment_blocks: blocks::State,
}
impl State {
    pub(crate) fn new(model: Persona) -> Self {
        Self {
            model,
            command_lines: BTreeMap::new(),
            environment_blocks: blocks::State::default(),
        }
    }
    pub(crate) fn fixture() -> Self {
        Self::fixture_with_logical(12).expect("validated generated processor profile")
    }
    pub(crate) fn fixture_with_logical(logical: u32) -> Result<Self> {
        let mut config = PersonaConfig::fixture();
        config.logical_processors = logical;
        // The existing generated VFS starts in C:\workspace. Its command line
        // and current-directory APIs must describe that same guest directory.
        config.current_directory = r"C:\workspace".into();
        let mut model = Persona::new(config)?;
        let mut process = ProcessConfig::fixture();
        process.image_path = r"C:\workspace\generated-fixture.exe".into();
        model
            .add_process(OWNER, process)
            .expect("validated generated process literals");
        Ok(Self::new(model))
    }
    pub(crate) fn environment_blocks_report(&self) -> EnvironmentBlockReport {
        blocks::report(self)
    }
    pub(crate) fn validate_cpu(&self, profile: &emumee_core::cpu::CpuProfile) -> Result<()> {
        ensure!(
            Some(self.model.config().logical_processors)
                == profile.cores.checked_mul(profile.threads_per_core),
            "Persona NUMBER_OF_PROCESSORS differs from modeled CPU topology"
        );
        Ok(())
    }
    fn overlaps(&self, address: u64, size: u64) -> Result<bool> {
        let end = address
            .checked_add(size.max(1))
            .ok_or_else(|| anyhow::anyhow!("Persona allocation change range overflow"))?;
        Ok(self
            .command_lines
            .values()
            .any(|text| address < text.address + text.size && text.address < end))
    }
}
/// Parent must call before VirtualFree and VirtualProtect planning, including
/// size==0 release. Retained system-owned command lines have no guest free API.
pub(crate) fn require_allocation_change(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
) -> Result<()> {
    ensure!(
        !engine.get_data().apis.persona.overlaps(address, size)?,
        "Guest allocation change overlaps system-owned command-line storage"
    );
    blocks::require_change(&engine.get_data().apis.persona, address, size)?;
    Ok(())
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    if let Some(binding) = blocks::definition(module, name) {
        return Some(binding);
    }
    let kernel = matches!(module, "kernel32" | "kernelbase");
    let environment = kernel
        || matches!(
            module,
            "api-ms-win-core-processenvironment-l1-1-0"
                | "api-ms-win-core-processenvironment-l1-2-0"
        );
    let system = kernel || module == "api-ms-win-core-sysinfo-l1-1-0";
    let file = kernel
        || matches!(
            module,
            "api-ms-win-core-file-l1-1-0" | "api-ms-win-core-file-l1-2-0"
        );
    let wide = name.ends_with('W');
    let ansi = if wide {
        Encoding::Utf16
    } else {
        Encoding::Cp1252
    };
    let env = if wide {
        Encoding::Utf16
    } else {
        Encoding::Cp437
    };
    Some(match name {
        "GetEnvironmentVariableA" | "GetEnvironmentVariableW" if environment => {
            (Call::Variable(env), 3, T::U32)
        }
        "SetEnvironmentVariableA" | "SetEnvironmentVariableW" if environment => {
            (Call::Set(env), 2, T::U32)
        }
        "ExpandEnvironmentStringsA" | "ExpandEnvironmentStringsW" if environment => {
            (Call::Expand(env), 3, T::U32)
        }
        "GetCommandLineA" | "GetCommandLineW" if environment => {
            (Call::CommandLine(ansi), 0, T::Pointer)
        }
        "GetCurrentDirectoryA" | "GetCurrentDirectoryW" if environment => {
            (Call::Directory(Directory::Current, ansi), 2, T::U32)
        }
        "GetWindowsDirectoryA"
        | "GetWindowsDirectoryW"
        | "GetSystemWindowsDirectoryA"
        | "GetSystemWindowsDirectoryW"
            if system =>
        {
            (Call::Directory(Directory::Windows, ansi), 2, T::U32)
        }
        "GetSystemDirectoryA" | "GetSystemDirectoryW" if system => {
            (Call::Directory(Directory::System, ansi), 2, T::U32)
        }
        "GetTempPathA" | "GetTempPathW" if file => (
            Call::Directory(
                Directory::Temp,
                if wide {
                    Encoding::Utf16
                } else {
                    Encoding::Utf8
                },
            ),
            2,
            T::U32,
        ),
        "GetComputerNameA" | "GetComputerNameW" if system => (Call::Computer(ansi), 2, T::U32),
        "GetComputerNameExA" | "GetComputerNameExW" if system => {
            (Call::ComputerEx(ansi), 3, T::U32)
        }
        "GetUserNameA" | "GetUserNameW" if module == "advapi32" => (Call::User(ansi), 2, T::U32),
        _ => return None,
    })
}
fn input(engine: &Unicorn<Trace>, address: u64, encoding: Encoding) -> Result<String> {
    if address == 0 {
        return Err(PersonaError {
            win32: 87,
            reason: "null guest persona input string",
        }
        .into());
    }
    let mut bytes = Vec::new();
    for index in 0..=persona::MAX_STRING_UNITS as u64 {
        let at = address
            .checked_add(index * encoding.width() as u64)
            .ok_or(PersonaError {
                win32: 87,
                reason: "guest persona input pointer overflow",
            })?;
        if !engine
            .get_data()
            .apis
            .memory
            .allows(at, encoding.width() as u64, P::READ)
        {
            return Err(PersonaError {
                win32: 998,
                reason: "unreadable guest persona input string",
            }
            .into());
        }
        let unit = read(engine, at, encoding.width() as u64)?;
        if unit.iter().all(|byte| *byte == 0) {
            return encoding.decode(&bytes).map_err(Into::into);
        }
        bytes.extend(unit);
    }
    Err(PersonaError {
        win32: 87,
        reason: "unterminated or oversized guest persona input string",
    }
    .into())
}
fn ordinary_failure(engine: &mut Unicorn<Trace>, error: anyhow::Error) -> Result<u64> {
    if let Some(error) = error.downcast_ref::<PersonaError>() {
        ensure!(error.win32 != 50, "Unsupported persona profile: {error}");
        engine.get_data_mut().apis.last_error = error.win32;
        return Ok(0);
    }
    Err(error)
}
fn apply(engine: &mut Unicorn<Trace>, plan: BufferPlan, output: u64, count: u64) -> Result<u64> {
    let mut writes = Vec::new();
    if let Some(bytes) = plan.bytes {
        writes.push((output, bytes));
    }
    if let Some(value) = plan.count {
        writes.push((count, value.to_le_bytes().to_vec()));
    }
    if writes.iter().any(|(at, bytes)| {
        !engine
            .get_data()
            .apis
            .memory
            .allows(*at, bytes.len() as u64, P::WRITE)
    }) {
        engine.get_data_mut().apis.last_error = 998;
        return Ok(0);
    }
    for (at, bytes) in writes {
        crate::cpu::write(engine, at, &bytes)?;
    }
    if let Some(error) = plan.last_error {
        engine.get_data_mut().apis.last_error = error;
    }
    Ok(plan.result as u64)
}
fn count(engine: &Unicorn<Trace>, at: u64) -> Result<u32> {
    if at == 0 {
        return Err(PersonaError {
            win32: 87,
            reason: "null persona count pointer",
        }
        .into());
    }
    if !engine.get_data().apis.memory.allows(at, 4, P::READ) {
        return Err(PersonaError {
            win32: 998,
            reason: "unreadable persona count pointer",
        }
        .into());
    }
    Ok(u32::from_le_bytes(read(engine, at, 4)?.try_into().unwrap()))
}
fn stable_command_line(engine: &mut Unicorn<Trace>, encoding: Encoding) -> Result<u64> {
    let key = (OWNER, if encoding == Encoding::Utf16 { 1 } else { 0 });
    if let Some(text) = engine.get_data().apis.persona.command_lines.get(&key) {
        ensure!(
            engine
                .get_data()
                .apis
                .memory
                .allows(text.address, text.bytes as u64, P::READ),
            "System-owned guest command line no longer has its readable backing"
        );
        return Ok(text.address);
    }
    let payload = engine
        .get_data()
        .apis
        .persona
        .model
        .command_line(OWNER, encoding)?;
    let state = &engine.get_data().apis;
    let plan = match state.allocations.allocate(
        &state.memory,
        0,
        payload.len() as u64,
        vm::RESERVE | vm::COMMIT,
        2,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            engine.get_data_mut().apis.last_error = error.win32;
            return Ok(0);
        }
    };
    let address = plan.result;
    let size = (payload.len() as u64).div_ceil(4096) * 4096;
    allocation::apply(engine, plan)?;
    // Model writes can initialize read-only guest pages, as for PE/shared-data
    // initialization. Native guest stores and API helpers still see P::READ.
    engine.get_data_mut().apis.persona.command_lines.insert(
        key,
        StableText {
            address,
            size,
            bytes: payload.len(),
        },
    );
    crate::cpu::write(engine, address, &payload)?;
    Ok(address)
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "User persona APIs are outside the kernel target profile"
    );
    engine
        .get_data()
        .apis
        .persona
        .validate_cpu(&engine.get_data().cpu.profile)?;
    let result = (|| -> Result<u64> {
        match call {
            Call::Variable(encoding) => {
                let name = input(engine, args[0], encoding)?;
                let plan = engine.get_data().apis.persona.model.variable(
                    OWNER,
                    &name,
                    encoding,
                    args[2] as u32,
                    args[1] != 0,
                )?;
                apply(engine, plan, args[1], 0)
            }
            Call::Set(encoding) => {
                let name = input(engine, args[0], encoding)?;
                let value = if args[1] == 0 {
                    None
                } else {
                    Some(input(engine, args[1], encoding)?)
                };
                if value.is_none()
                    && engine
                        .get_data()
                        .apis
                        .persona
                        .model
                        .environment(OWNER)?
                        .get(&name)?
                        .is_none()
                {
                    bail!(
                        "Deleting an absent environment variable requires a verified native error contract"
                    );
                }
                engine.get_data_mut().apis.persona.model.set_variable(
                    OWNER,
                    &name,
                    value.as_deref(),
                )?;
                // https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-setenvironmentvariablew
                // No host/system/other-process environment is modified.
                Ok(1)
            }
            Call::Expand(encoding) => {
                let text = input(engine, args[0], encoding)?;
                ensure!(
                    args[0] != args[1],
                    "In-place ExpandEnvironmentStrings is outside the documented profile"
                );
                let plan = engine.get_data().apis.persona.model.expand(
                    OWNER,
                    &text,
                    encoding,
                    args[2] as u32,
                    args[1] != 0,
                )?;
                if let Some(bytes) = &plan.bytes {
                    let input_end = args[0]
                        .checked_add(encoding.encode(&text, true).len() as u64)
                        .ok_or_else(|| {
                            anyhow::anyhow!("Environment expansion input range overflow")
                        })?;
                    let output_end = args[1].checked_add(bytes.len() as u64).ok_or_else(|| {
                        anyhow::anyhow!("Environment expansion output range overflow")
                    })?;
                    ensure!(
                        args[0] >= output_end || args[1] >= input_end,
                        "Overlapping ExpandEnvironmentStrings buffers are outside the documented profile"
                    );
                }
                apply(engine, plan, args[1], 0)
            }
            Call::Directory(kind, encoding) => {
                let (capacity, output) = if matches!(kind, Directory::Current | Directory::Temp) {
                    (args[0] as u32, args[1])
                } else {
                    (args[1] as u32, args[0])
                };
                let plan = engine.get_data().apis.persona.model.directory(
                    OWNER,
                    kind,
                    encoding,
                    capacity,
                    output != 0,
                )?;
                apply(engine, plan, output, 0)
            }
            Call::Computer(encoding) | Call::User(encoding) => {
                let capacity = count(engine, args[1])?;
                let model = &engine.get_data().apis.persona.model;
                let plan = if matches!(call, Call::User(_)) {
                    model.user_name(encoding, capacity, args[0] != 0)?
                } else {
                    model.computer_name(encoding, capacity, args[0] != 0)?
                };
                apply(engine, plan, args[0], args[1])
            }
            Call::ComputerEx(encoding) => {
                let capacity = count(engine, args[2])?;
                let plan = engine.get_data().apis.persona.model.computer_name_ex(
                    args[0] as u32,
                    encoding,
                    capacity,
                    args[1] != 0,
                )?;
                apply(engine, plan, args[1], args[2])
            }
            Call::CommandLine(encoding) => stable_command_line(engine, encoding),
            Call::Blocks(call) => blocks::invoke(engine, args, call),
        }
    })();
    match result {
        Ok(value) => Ok(value),
        Err(error) => ordinary_failure(engine, error),
    }
}
