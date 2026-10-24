//! Bounded legacy CRT formatting over guest integer slots and checked memory.
//! No host printf, libc, locale, FILE pointer or variadic host call is used.
use super::*;
use emumee_core::crt_format::{self as format, BufferMode, Format, FormatError, Profile, Reader};
const OWNER: u64 = 1024;
#[derive(Clone, Debug, Serialize)]
pub struct KernelFormatObservation {
    pub api: &'static str,
    pub pc: Option<u64>,
    pub instruction_ordinal: u64,
    pub format_address: u64,
    pub buffer: Option<u64>,
    pub result: u64,
    pub text: String,
    pub preview_truncated: bool,
}
#[derive(Default)]
pub(crate) struct KernelFormatting {
    observations: Vec<KernelFormatObservation>,
    omitted: u64,
}
#[derive(Debug, Serialize)]
pub struct KernelFormattingReport {
    pub observations: Vec<KernelFormatObservation>,
    pub limit: usize,
    pub omitted: u64,
    pub scope: &'static str,
}
pub(crate) fn kernel_report(engine: &Unicorn<Trace>) -> Option<KernelFormattingReport> {
    let state = &engine.get_data().apis;
    state.kernel_mode.then(|| KernelFormattingReport {
        observations: state.kernel_formatting.observations.clone(),
        limit: 128,
        omitted: state.kernel_formatting.omitted,
        scope: "Last128 successful kernel formatting operations, at most1024 UTF-16 units each, copied from actual rendered/written output before guest encryption or release. Passive telemetry; no guest memory reads, time, status or formatting changes.",
    })
}
fn record(
    engine: &mut Unicorn<Trace>,
    api: &'static str,
    format_address: u64,
    buffer: Option<u64>,
    result: u64,
    units: &[u16],
) {
    if !engine.get_data().apis.kernel_mode {
        return;
    }
    let observation = KernelFormatObservation {
        api,
        pc: engine.pc_read().ok(),
        instruction_ordinal: engine.get_data().instructions,
        format_address,
        buffer,
        result,
        text: String::from_utf16_lossy(&units[..units.len().min(1024)]),
        preview_truncated: units.len() > 1024,
    };
    let state = &mut engine.get_data_mut().apis.kernel_formatting;
    if state.observations.len() == 128 {
        state.observations.remove(0);
        state.omitted += 1;
    }
    state.observations.push(observation);
}
#[derive(Clone, Copy)]
pub(super) enum Call {
    WideConsole(bool),
    WideBuffer,
    Secure(bool),
    CommonWide,
    CommonNarrow,
    KernelDebug,
}
pub(super) fn definition(
    architecture: Architecture,
    module: &str,
    name: &str,
) -> Option<(Call, usize, T)> {
    let legacy = module == "msvcrt";
    let kernel = module == "ntoskrnl";
    let common = matches!(
        module,
        "ucrtbase" | "api-ms-win-crt-private-l1-1-0" | "api-ms-win-crt-stdio-l1-1-0"
    );
    Some(match name {
        "DbgPrintEx" if kernel => (Call::KernelDebug, 3, T::U32),
        "wprintf" if legacy => (Call::WideConsole(false), 1, T::U32),
        "fwprintf" if legacy => (Call::WideConsole(true), 2, T::U32),
        "_vsnwprintf" if legacy => (Call::WideBuffer, 4, T::U32),
        "swprintf_s" if legacy => (Call::Secure(false), 3, T::U32),
        "_snwprintf_s" if legacy => (Call::Secure(true), 4, T::U32),
        "__stdio_common_vswprintf" | "_o___stdio_common_vswprintf" if common => (
            Call::CommonWide,
            if architecture == Architecture::X86 {
                7
            } else {
                6
            },
            T::U32,
        ),
        "__stdio_common_vfprintf" | "_o___stdio_common_vfprintf" if common => (
            Call::CommonNarrow,
            if architecture == Architecture::X86 {
                6
            } else {
                5
            },
            T::U32,
        ),
        _ => return None,
    })
}
fn text(engine: &Unicorn<Trace>, address: u64, wide: bool) -> format::Result<String> {
    if address == 0 {
        return Ok("(null)".into());
    }
    let width = if wide { 2 } else { 1 };
    let mut bytes = Vec::new();
    for index in 0..format::MAX_FORMAT {
        let at = address
            .checked_add((index * width) as u64)
            .ok_or(FormatError("guest string pointer overflow"))?;
        let unit = read(engine, at, width as u64)
            .map_err(|_| FormatError("unreadable guest format/string memory"))?;
        if unit.iter().all(|b| *b == 0) {
            return if wide {
                let units: Vec<_> = bytes
                    .chunks_exact(2)
                    .map(|b: &[u8]| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                String::from_utf16(&units).map_err(|_| FormatError("malformed UTF16 format/string"))
            } else {
                Ok(bytes.into_iter().map(char::from).collect())
            };
        }
        bytes.extend(unit);
    }
    Err(FormatError("guest format/string exceeds string limit"))
}
fn slot(engine: &Unicorn<Trace>, index: usize) -> format::Result<u64> {
    let frame = Frame(engine);
    let architecture = frame.architecture();
    if architecture == Architecture::X64 && index < 4 {
        return frame
            .register([R::Cx, R::Dx, R::R8, R::R9][index])
            .map_err(|_| FormatError("unreadable variadic register"));
    }
    let sp = frame
        .register(R::Sp)
        .map_err(|_| FormatError("unreadable variadic stack pointer"))?;
    let offset = if architecture == Architecture::X64 {
        0x28 + (index - 4) * 8
    } else {
        4 + index * 4
    };
    let address = sp
        .checked_add(offset as u64)
        .ok_or(FormatError("variadic stack pointer overflow"))?;
    if architecture == Architecture::X86
        && address.checked_add(4).is_none_or(|end| end > 1u64 << 32)
    {
        return Err(FormatError("variadic x86 stack range overflow"));
    }
    pointer(engine, address)
}
fn pointer(engine: &Unicorn<Trace>, address: u64) -> format::Result<u64> {
    let width = engine.get_data().architecture.width();
    let bytes = read(engine, address, width as u64)
        .map_err(|_| FormatError("unreadable guest variadic slot"))?;
    Ok(if width == 4 {
        u32::from_le_bytes(bytes.try_into().unwrap()) as u64
    } else {
        u64::from_le_bytes(bytes.try_into().unwrap())
    })
}
enum Arguments {
    Direct(usize),
    List(u64),
}
struct GuestArguments<'a, 'b> {
    engine: &'a Unicorn<'b, Trace>,
    source: Arguments,
    index: usize,
}
impl Reader for GuestArguments<'_, '_> {
    fn next(&mut self) -> format::Result<u64> {
        if self.index >= format::MAX_ARGUMENTS {
            return Err(FormatError("format argument limit exceeded"));
        }
        let index = self.index;
        self.index += 1;
        match self.source {
            Arguments::Direct(fixed) => slot(self.engine, fixed + index),
            Arguments::List(base) => {
                let at = base
                    .checked_add((index * self.engine.get_data().architecture.width()) as u64)
                    .ok_or(FormatError("variadic list pointer overflow"))?;
                pointer(self.engine, at)
            }
        }
    }
    fn string(&self, address: u64, wide: bool) -> format::Result<String> {
        text(self.engine, address, wide)
    }
}
fn rendered(
    engine: &Unicorn<Trace>,
    address: u64,
    profile: Profile,
    source: Arguments,
) -> Result<String> {
    let fmt = text(engine, address, profile != Profile::NarrowConsole)?;
    let parsed = Format::parse(&fmt, profile)?;
    let mut reader = GuestArguments {
        engine,
        source,
        index: 0,
    };
    Ok(parsed.render(&mut reader, engine.get_data().architecture.width())?)
}
fn common(args: &[u64], architecture: Architecture) -> (u64, &[u64]) {
    if architecture == Architecture::X86 {
        (
            (args[0] & 0xffffffff) | ((args[1] & 0xffffffff) << 32),
            &args[2..],
        )
    } else {
        (args[0], &args[1..])
    }
}
fn output(
    engine: &mut Unicorn<Trace>,
    buffer: u64,
    count: u64,
    value: &str,
    mode: BufferMode,
    observation: Option<(&'static str, u64)>,
) -> Result<u64> {
    ensure!(
        buffer != 0 && count > 0 && count <= format::MAX_OUTPUT as u64,
        "CRT formatting profile unsupported: invalid wide output destination/capacity"
    );
    if !matches!(mode, BufferMode::Legacy) {
        require(engine, buffer, count * 2, P::WRITE)?;
    }
    let plan = format::wide_buffer(value, count as usize, mode)?;
    require(engine, buffer, plan.bytes.len() as u64, P::WRITE)?;
    let effect = crate::cpu::write(engine, buffer, &plan.bytes);
    super::kernel_rtl::format_write_result(engine, effect)?;
    let result = plan.result as u32 as u64;
    if engine.get_data().apis.kernel_mode
        && let Some((api, format_address)) = observation
    {
        let mut units = plan
            .bytes
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .collect::<Vec<_>>();
        if units.last() == Some(&0) {
            units.pop();
        }
        record(engine, api, format_address, Some(buffer), result, &units);
    }
    Ok(result)
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    let architecture = engine.get_data().architecture;
    match call {
        Call::KernelDebug => {
            // The first three fixed arguments are ComponentId, Level, Format.
            // Only the bounded formatter may read further guest variadic slots.
            // No host debugger, kernel logger, or output stream is invoked.
            let value = rendered(
                engine,
                args[2],
                Profile::NarrowConsole,
                Arguments::Direct(3),
            )?;
            record(
                engine,
                "DbgPrintEx",
                args[2],
                None,
                0,
                &value.encode_utf16().collect::<Vec<_>>(),
            );
            // Documented DbgPrintEx success status. The saved Python53 adapter
            // returned the rendered length instead; that is compatibility data.
            Ok(0)
        }
        Call::WideConsole(stream) => {
            let (descriptor, format_index) = if stream {
                (
                    engine
                        .get_data()
                        .apis
                        .crt_stdio
                        .model
                        .fileno(OWNER, args[0])?,
                    1,
                )
            } else {
                (1, 0)
            };
            ensure!(
                matches!(descriptor, 1 | 2),
                "CRT formatting profile unsupported: nonstandard output FILE"
            );
            let value = rendered(
                engine,
                args[format_index],
                Profile::WideConsole,
                Arguments::Direct(format_index + 1),
            )?;
            let result = value.encode_utf16().count() as u64;
            engine
                .get_data_mut()
                .apis
                .crt_stdio
                .model
                .formatted_write(OWNER, descriptor, &value, true)?;
            Ok(result)
        }
        Call::WideBuffer => {
            ensure!(
                args[3] != 0,
                "CRT formatting profile unsupported: null variadic list"
            );
            let value = rendered(
                engine,
                args[2],
                Profile::WideBuffer,
                Arguments::List(args[3]),
            )?;
            output(
                engine,
                args[0],
                args[1],
                &value,
                BufferMode::Legacy,
                Some(("_vsnwprintf", args[2])),
            )
        }
        Call::Secure(counted) => {
            let (buffer, size) = (args[0], args[1]);
            ensure!(
                buffer != 0 && size > 0 && size <= format::MAX_OUTPUT as u64,
                "CRT formatting profile unsupported: invalid secure output destination/capacity"
            );
            let truncate = counted
                && args[2]
                    == if architecture == Architecture::X86 {
                        u32::MAX as u64
                    } else {
                        u64::MAX
                    };
            let count = if counted && !truncate {
                size.min(args[2].saturating_add(1))
            } else {
                size
            };
            let fixed = if counted { 4 } else { 3 };
            let format_index = fixed - 1;
            require(engine, buffer, count * 2, P::WRITE)?;
            let value = rendered(
                engine,
                args[format_index],
                Profile::WideBuffer,
                Arguments::Direct(fixed),
            )?;
            output(
                engine,
                buffer,
                count,
                &value,
                if truncate {
                    BufferMode::Truncate
                } else {
                    BufferMode::Secure
                },
                Some((
                    if counted {
                        "_snwprintf_s"
                    } else {
                        "swprintf_s"
                    },
                    args[format_index],
                )),
            )
        }
        Call::CommonWide => {
            let (options, args) = common(args, architecture);
            ensure!(
                options & !3 == 0 && args[3] == 0,
                "CRT formatting profile unsupported: locale or common formatting options"
            );
            ensure!(
                args[4] != 0,
                "CRT formatting profile unsupported: null variadic list"
            );
            let value = rendered(
                engine,
                args[2],
                Profile::WideBuffer,
                Arguments::List(args[4]),
            )?;
            output(engine, args[0], args[1], &value, BufferMode::Legacy, None)
        }
        Call::CommonNarrow => {
            let (options, args) = common(args, architecture);
            ensure!(
                options & !3 == 0 && args[2] == 0,
                "CRT formatting profile unsupported: locale or common formatting options"
            );
            ensure!(
                args[1] != 0 && args[3] != 0,
                "CRT formatting profile unsupported: null common narrow format/list"
            );
            let descriptor = engine
                .get_data()
                .apis
                .crt_stdio
                .model
                .fileno(OWNER, args[0])?;
            ensure!(
                matches!(descriptor, 1 | 2),
                "CRT formatting profile unsupported: nonstandard output FILE"
            );
            let value = rendered(
                engine,
                args[1],
                Profile::NarrowConsole,
                Arguments::List(args[3]),
            )?;
            let result = value.len() as u64;
            engine
                .get_data_mut()
                .apis
                .crt_stdio
                .model
                .formatted_write(OWNER, descriptor, &value, false)?;
            Ok(result)
        }
    }
}

#[cfg(test)]
mod kernel_debug_tests {
    use super::*;

    fn engine(architecture: Architecture) -> crate::NativeEngine {
        let mut engine = crate::new_engine(architecture).unwrap();
        engine
            .get_data_mut()
            .apis
            .target(architecture, true)
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(
                0x10000,
                8192,
                P::RW,
                Some(4),
                "generated DbgPrintEx fixture",
            )
            .unwrap();
        engine
            .mem_map(0x10000, 8192, Prot::READ | Prot::WRITE)
            .unwrap();
        engine.get_data_mut().apis.last_error = 0x12345678;
        engine
    }

    #[test]
    fn kernel_format_snapshots_preserve_actual_truncated_output_and_bound_debug_history() {
        let mut engine = engine(Architecture::X64);
        let result = output(
            &mut engine,
            0x10000,
            3,
            "abcdef",
            BufferMode::Legacy,
            Some(("_vsnwprintf", 0x11000)),
        )
        .unwrap();
        assert_eq!(result, u32::MAX as u64);
        assert_eq!(engine.mem_read_as_vec(0x10000, 6).unwrap(), b"a\0b\0c\0");
        let report = kernel_report(&engine).unwrap();
        assert_eq!(report.observations[0].text, "abc");
        assert_eq!(report.observations[0].result, result);
        assert!(!report.observations[0].preview_truncated);
        let message = format!("{}\0", "x".repeat(1100));
        engine.mem_write(0x10200, message.as_bytes()).unwrap();
        for _ in 0..129 {
            assert_eq!(
                invoke(&mut engine, &[0x4d, 0, 0x10200], Call::KernelDebug).unwrap(),
                0
            );
        }
        let report = kernel_report(&engine).unwrap();
        assert_eq!(report.observations.len(), 128);
        assert_eq!(report.omitted, 2);
        assert!(
            report.observations.iter().all(|row| row.api == "DbgPrintEx"
                && row.text.len() == 1024
                && row.preview_truncated)
        );
        assert_eq!(
            engine.mem_read_as_vec(0x10200, message.len()).unwrap(),
            message.as_bytes()
        );
        assert_eq!(engine.get_data().apis.last_error, 0x12345678);
    }

    #[test]
    fn generated_kernel_debug_fixture_has_cdecl_abi_bounded_varargs_and_status_return() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let binding = super::super::definition(architecture, "ntoskrnl.exe", "DbgPrintEx");
            assert!(matches!(binding.model, Model::CrtFormat(Call::KernelDebug)));
            assert_eq!(binding.count, 3);
            assert_eq!(binding.convention, C::Cdecl);
            assert_eq!(binding.returns, T::U32);
            let mut engine = engine(architecture);
            engine
                .mem_write(0x10200, b"fixture count=%u\r\n\0")
                .unwrap();
            if architecture == Architecture::X64 {
                engine.reg_write(RegisterX86::R9, 42).unwrap();
            } else {
                engine.reg_write(RegisterX86::ESP, 0x11000).unwrap();
                engine.mem_write(0x11010, &42u32.to_le_bytes()).unwrap();
            }
            let result = invoke(&mut engine, &[0x4d, 0, 0x10200], Call::KernelDebug).unwrap();
            assert_eq!(result, 0);
            assert_eq!(engine.get_data().apis.last_error, 0x12345678);
            assert!(
                engine
                    .get_data()
                    .apis
                    .crt_stdio
                    .model
                    .report()
                    .console
                    .write_events
                    .is_empty()
            );
            for module in ["cng.sys", "msvcrt.dll", "ntdll.dll"] {
                assert!(!matches!(
                    super::super::definition(architecture, module, "DbgPrintEx").model,
                    Model::CrtFormat(_)
                ));
            }
        }
    }

    #[test]
    fn generated_kernel_debug_fixture_refuses_unmodeled_conversion_and_unreadable_format() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            engine.mem_write(0x10200, b"fixture %q\0").unwrap();
            assert!(
                invoke(&mut engine, &[0x4d, 0, 0x10200], Call::KernelDebug)
                    .unwrap_err()
                    .to_string()
                    .contains("conversion is not modeled")
            );
            assert!(
                invoke(&mut engine, &[0x4d, 0, 0x20000], Call::KernelDebug)
                    .unwrap_err()
                    .to_string()
                    .contains("unreadable guest format/string memory")
            );
            assert_eq!(engine.get_data().apis.last_error, 0x12345678);
        }
    }
}
