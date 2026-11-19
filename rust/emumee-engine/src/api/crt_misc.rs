//! Remaining legacy CRT runtime services: pseudo-random numbers, signals, the
//! command processor boundary, clock readings, integer and floating-point
//! control helpers, and the exception-dispatch entry points. Every value is
//! derived from modeled state or the one persona clock; nothing reaches a host
//! allocator, host clock, host signal or host command processor.
use super::*;
use anyhow::Context;

/// Characters a command string may carry before the call is refused.
const MAX_COMMAND: u64 = 4096;
const FILETIME_1970: u64 = 116_444_736_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Call {
    Random,
    Seed,
    Signal,
    System,
    Time,
    Clock,
    Absolute,
    ControlFp(bool),
    /// Filters and handlers whose frozen result is a documented literal.
    Literal(u64),
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    if !matches!(
        module,
        "msvcrt" | "ucrtbase" | "api-ms-win-crt-private-l1-1-0" | "vcruntime140"
    ) {
        return None;
    }
    let name = name.strip_prefix("_o_").unwrap_or(name);
    Some(match name {
        "rand" => (Call::Random, 0, T::U32),
        "srand" => (Call::Seed, 1, T::Void),
        "signal" => (Call::Signal, 2, T::Pointer),
        "system" => (Call::System, 1, T::U32),
        "time" => (Call::Time, 1, T::U32),
        "clock" => (Call::Clock, 0, T::U32),
        "abs" | "labs" => (Call::Absolute, 1, T::U32),
        "_controlfp" => (Call::ControlFp(false), 2, T::U32),
        "_controlfp_s" => (Call::ControlFp(true), 3, T::U32),
        // EXCEPTION_CONTINUE_SEARCH and ExceptionContinueExecution: the frozen
        // handlers decline every exception they are handed.
        "_XcptFilter" => (Call::Literal(0), 2, T::U32),
        "__CxxFrameHandler" => (Call::Literal(0), 4, T::U32),
        // EXCEPTION_EXECUTE_HANDLER, as the frozen filters report.
        "_except_handler3" => (Call::Literal(1), 4, T::U32),
        "_seh_filter_dll" | "_seh_filter_exe" => (Call::Literal(1), 2, T::U32),
        // No exception is ever in flight in this profile, so the accessors
        // report none rather than leaving the result register undefined.
        "__current_exception" | "__current_exception_context" => (Call::Literal(0), 0, T::Pointer),
        _ => return None,
    })
}
#[derive(Default)]
pub(super) struct State {
    seed: Option<u32>,
    control: Option<u32>,
    handlers: Vec<(u32, u64)>,
    commands: Vec<String>,
    start: Option<u64>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub random_seed: Option<u32>,
    pub floating_control: Option<u32>,
    pub signal_handlers: Vec<(u32, u64)>,
    pub refused_commands: Vec<String>,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().apis.crt_misc;
    if state.seed.is_none()
        && state.control.is_none()
        && state.handlers.is_empty()
        && state.commands.is_empty()
    {
        return None;
    }
    Some(Report {
        random_seed: state.seed,
        floating_control: state.control,
        signal_handlers: state.handlers.clone(),
        refused_commands: state.commands.clone(),
        scope: "Modeled CRT pseudo-random, signal, command-processor and floating-point control state only. Signal handlers are recorded, never delivered; no command processor exists.",
    })
}
/// The documented Microsoft CRT generator, so a seeded guest sees the same
/// sequence the real runtime produces. The frozen reference returns a counter.
fn next(seed: &mut u32) -> u32 {
    *seed = seed.wrapping_mul(214_013).wrapping_add(2_531_011);
    (*seed >> 16) & 0x7fff
}
/// The default control word the Microsoft CRT installs: round to nearest, all
/// exceptions masked, and 53-bit precision where precision control exists.
fn default_control(architecture: Architecture) -> u32 {
    if architecture == Architecture::X86 {
        0x9_001f
    } else {
        0x8_001f
    }
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "CRT runtime services require a user process"
    );
    match call {
        Call::Literal(value) => Ok(value),
        Call::Random => {
            let mut seed = engine
                .get_data()
                .apis
                .crt_misc
                .seed
                .unwrap_or(1);
            let value = next(&mut seed);
            engine.get_data_mut().apis.crt_misc.seed = Some(seed);
            Ok(u64::from(value))
        }
        Call::Seed => {
            engine.get_data_mut().apis.crt_misc.seed = Some(args[0] as u32);
            Ok(0)
        }
        // Handlers are recorded and never delivered: this profile raises no CRT
        // signal, so every known signal reports SIG_IGN and the rest SIG_ERR.
        Call::Signal => {
            const KNOWN: [u32; 7] = [2, 4, 8, 11, 15, 21, 22];
            if !KNOWN.contains(&(args[0] as u32)) {
                return Ok(u64::MAX);
            }
            if args[1] > 2 {
                require(engine, args[1], 1, P::EXECUTE)?;
            }
            let state = &mut engine.get_data_mut().apis.crt_misc;
            if state.handlers.len() < 64 {
                state.handlers.push((args[0] as u32, args[1]));
            }
            Ok(1)
        }
        // No command processor exists. The request is recorded and refused,
        // exactly as a runtime without a shell reports it.
        Call::System => {
            if args[0] == 0 {
                return Ok(0);
            }
            let mut text = Vec::new();
            for index in 0..MAX_COMMAND {
                let byte = read(engine, args[0] + index, 1)?[0];
                if byte == 0 {
                    break;
                }
                text.push(byte);
            }
            ensure!(
                text.len() < MAX_COMMAND as usize,
                "CRT command string exceeds the modeled bound"
            );
            let state = &mut engine.get_data_mut().apis.crt_misc;
            if state.commands.len() < 64 {
                state.commands.push(String::from_utf8_lossy(&text).into_owned());
            }
            Ok(u64::MAX)
        }
        // Legacy msvcrt time_t is 32 bits wide, taken from the persona clock.
        Call::Time => {
            let filetime = engine.get_data().clock.utc_filetime;
            let seconds = filetime
                .checked_sub(FILETIME_1970)
                .context("Persona clock predates the CRT epoch")?
                / 10_000_000;
            let value = u32::try_from(seconds).context("CRT time_t overflow")?;
            if args[0] != 0 {
                require(engine, args[0], 4, P::WRITE)?;
                crate::cpu::write(engine, args[0], &value.to_le_bytes())?;
            }
            Ok(u64::from(value))
        }
        // Milliseconds of guest execution since CRT startup, at CLOCKS_PER_SEC.
        Call::Clock => {
            let ticks = engine.get_data().clock.tick64();
            let state = &mut engine.get_data_mut().apis.crt_misc;
            let start = *state.start.get_or_insert(ticks);
            Ok(ticks.saturating_sub(start))
        }
        Call::Absolute => Ok(u64::from((args[0] as u32 as i32).unsigned_abs())),
        // Only a query or a request that leaves the modeled control word
        // unchanged is accepted; changing rounding, precision or exception masks
        // would change arithmetic this profile does not model.
        Call::ControlFp(secure) => {
            let architecture = engine.get_data().architecture;
            let current = *engine
                .get_data_mut()
                .apis
                .crt_misc
                .control
                .get_or_insert(default_control(architecture));
            let (new, mask) = if secure {
                (args[1] as u32, args[2] as u32)
            } else {
                (args[0] as u32, args[1] as u32)
            };
            const MODELED: u32 = 0x8_001f | 0x300 | 0x3_0000 | 0x4_0000 | 0x0c0;
            ensure!(
                mask & !MODELED == 0,
                "CRT floating-point control mask 0x{mask:x} is not modeled"
            );
            ensure!(
                new & mask == current & mask,
                "Changing the CRT floating-point control word is not modeled"
            );
            if secure {
                if args[0] != 0 {
                    require(engine, args[0], 4, P::WRITE)?;
                    crate::cpu::write(engine, args[0], &current.to_le_bytes())?;
                }
                return Ok(0);
            }
            Ok(u64::from(current))
        }
    }
}
