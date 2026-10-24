//! Exact NTOS Unicode/string/buffer-format adapters; guest Pool remains sole
//! allocation authority. No host kernel/CRT, second allocator or FILE identity.
use super::*;
use emumee_core::kernel_rtl::{self as rtl, Counted};
use sha2::{Digest, Sha256};
const USTR: u32 = u32::from_le_bytes(*b"Ustr");
const OWNED_LIMIT: u64 = 4096;
#[derive(Clone, Copy)]
pub(super) enum Call {
    Time(kernel_time::Call),
    Init,
    Duplicate,
    Free,
    Crt(crt::Call),
    Format(crt_format::Call, &'static str),
}
pub(super) fn definition(name: &str) -> Option<(Call, usize, C, T)> {
    Some(match name {
        "ExSystemTimeToLocalTime" => (Call::Time(kernel_time::Call::Local), 2, C::Stdcall, T::Void),
        "RtlTimeToTimeFields" => (
            Call::Time(kernel_time::Call::Fields),
            2,
            C::Stdcall,
            T::Void,
        ),
        "RtlInitUnicodeString" => (Call::Init, 2, C::Stdcall, T::Void),
        "RtlDuplicateUnicodeString" => (Call::Duplicate, 3, C::Stdcall, T::U32),
        "RtlFreeUnicodeString" => (Call::Free, 1, C::Stdcall, T::Void),
        "wcslen" => (
            Call::Crt(crt::Call::Length {
                wide: true,
                bounded: false,
            }),
            1,
            C::Cdecl,
            T::Pointer,
        ),
        "strnlen" => (
            Call::Crt(crt::Call::Length {
                wide: false,
                bounded: true,
            }),
            2,
            C::Cdecl,
            T::Pointer,
        ),
        "strchr" => (
            Call::Crt(crt::Call::StringFind {
                wide: false,
                reverse: false,
            }),
            2,
            C::Cdecl,
            T::Pointer,
        ),
        "swprintf_s" => (
            Call::Format(crt_format::Call::Secure(false), "swprintf_s"),
            3,
            C::Cdecl,
            T::U32,
        ),
        "_vsnwprintf" => (
            Call::Format(crt_format::Call::WideBuffer, "_vsnwprintf"),
            4,
            C::Cdecl,
            T::U32,
        ),
        _ => return None,
    })
}
#[derive(Clone, Debug, Serialize)]
pub struct Owned {
    pub base: u64,
    pub requested: u64,
    pub allocation_ordinal: u64,
    pub live: bool,
    pub initialized: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub operation: &'static str,
    pub buffer: u64,
    pub length: u16,
    pub maximum: u16,
    pub status: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct FormatObservation {
    pub api: &'static str,
    pub buffer: u64,
    pub format_address: u64,
    pub result: i32,
    pub captured_units: usize,
    pub text: String,
    pub raw_utf16_sha256: String,
    pub truncated: bool,
}
#[derive(Default)]
pub(crate) struct State {
    owned: BTreeMap<u64, Owned>,
    lifetime_allocations: u64,
    native_failure: bool,
    active_irql: Option<u8>,
    events: Vec<Event>,
    events_omitted: u64,
    formats: Vec<FormatObservation>,
    formats_omitted: u64,
    capture_errors: u64,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub owned: Vec<Owned>,
    pub lifetime_allocations: u64,
    pub lifetime_limit: u64,
    pub live_allocations: usize,
    pub native_effect_failure: bool,
    pub events: Vec<Event>,
    pub events_omitted: u64,
    pub formatting: Vec<FormatObservation>,
    pub formatting_omitted: u64,
    pub capture_errors: u64,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Report {
    let s = &engine.get_data().apis.kernel_rtl;
    Report {
        owned: s.owned.values().cloned().collect(),
        lifetime_allocations: s.lifetime_allocations,
        lifetime_limit: OWNED_LIMIT,
        live_allocations: s.owned.values().filter(|x| x.live).count(),
        native_effect_failure: s.native_failure,
        events: s.events.clone(),
        events_omitted: s.events_omitted,
        formatting: s.formats.clone(),
        formatting_omitted: s.formats_omitted,
        capture_errors: s.capture_errors,
        scope: "Exact10 NTOS adapters including signed local-offset/time-fields conversion, raw counted UTF16 borrowed/init/duplicate, actual paged Pool Ustr provenance/free+generic-pool retirement and bounded strnlen. Existing bounded CRT integer/buffer grammar only. No arbitrary tag ownership, borrowed frees, host locale/FILE, other RTL conversions beyond bounded signed time fields/literal local offset, whole NTOS CRT namespace or pointer-ABA guarantee. Init MaximumLength includes NUL and free zeros descriptor; corrections of legacy omissions.",
    }
}
pub(crate) fn completion_error(engine: &Unicorn<Trace>) -> Option<String> {
    engine
        .get_data()
        .apis
        .kernel_rtl
        .native_failure
        .then(|| "Kernel RTL native effect failed; execution cannot resume".into())
}
/// API read/write preflight uses this only during these actual RTL calls.
/// Pure computation may consume nonpaged memory at elevated IRQL; paged Pool
/// may not be accessed above APC_LEVEL. No guessed host page residency.
pub(super) fn require_api_access(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    if size == 0
        || engine
            .get_data()
            .apis
            .kernel_rtl
            .active_irql
            .is_none_or(|level| level <= 1)
    {
        return Ok(());
    }
    let end = address
        .checked_add(size)
        .ok_or_else(|| anyhow::anyhow!("Kernel RTL range overflow"))?;
    ensure!(
        !engine
            .get_data()
            .apis
            .pool
            .allocations
            .values()
            .any(|a| a.paged && address < a.base + a.mapped && a.base < end),
        "Kernel RTL paged Pool access above APC_LEVEL"
    );
    Ok(())
}
fn effect<T>(engine: &mut Unicorn<Trace>, value: Result<T>) -> Result<T> {
    if value.is_err() {
        engine.get_data_mut().apis.kernel_rtl.native_failure = true;
    }
    value
}
pub(super) fn format_write_result(engine: &mut Unicorn<Trace>, result: Result<()>) -> Result<()> {
    if engine.get_data().apis.kernel_rtl.active_irql.is_some() {
        effect(engine, result)
    } else {
        result
    }
}
pub(super) fn write_effect(engine: &mut Unicorn<Trace>, address: u64, bytes: &[u8]) -> Result<()> {
    let result = crate::cpu::write(engine, address, bytes);
    effect(engine, result)
}
fn record(engine: &mut Unicorn<Trace>, operation: &'static str, value: Counted, status: u32) {
    let state = &mut engine.get_data_mut().apis.kernel_rtl;
    if state.events.len() < 128 {
        state.events.push(Event {
            operation,
            buffer: value.buffer,
            length: value.length,
            maximum: value.maximum,
            status,
        });
    } else {
        state.events_omitted = state.events_omitted.saturating_add(1);
    }
}
fn descriptor(engine: &Unicorn<Trace>, address: u64) -> Result<Counted> {
    let arch = engine.get_data().architecture;
    Ok(Counted::decode(
        arch,
        &read(engine, address, rtl::descriptor_size(arch) as u64)?,
    )?)
}
fn init(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let mut units = Vec::new();
    if args[1] != 0 {
        for index in 0..rtl::MAX_BYTES / 2 {
            let address = args[1]
                .checked_add(index as u64 * 2)
                .ok_or_else(|| anyhow::anyhow!("Kernel RTL initializer pointer overflow"))?;
            let bytes = read(engine, address, 2)?;
            let value = u16::from_le_bytes(bytes.try_into().unwrap());
            if value == 0 {
                break;
            }
            units.push(value);
        }
    }
    let plan = rtl::initialize(args[1], &units)?;
    let bytes = plan.encode(engine.get_data().architecture)?;
    require(engine, args[0], bytes.len() as u64, P::WRITE)?;
    write_effect(engine, args[0], &bytes)?;
    record(engine, "initialize", plan, 0);
    Ok(0)
}
fn duplicate(engine: &mut Unicorn<Trace>, args: &[u64], irql: u8) -> Result<u64> {
    let flags = args[0] as u32;
    if !rtl::flags_supported(flags) {
        record(
            engine,
            "duplicate",
            Counted::zero(),
            rtl::STATUS_INVALID_PARAMETER,
        );
        return Ok(rtl::STATUS_INVALID_PARAMETER.into());
    }
    ensure!(
        irql <= 1,
        "Kernel RTL paged Unicode duplication requires IRQL<=APC_LEVEL"
    );
    let source = descriptor(engine, args[1])?;
    let width = rtl::descriptor_size(engine.get_data().architecture) as u64;
    require(engine, args[2], width, P::WRITE)?;
    if rtl::duplicate_size(flags, source).is_err() {
        record(engine, "duplicate", source, rtl::STATUS_INVALID_PARAMETER);
        return Ok(rtl::STATUS_INVALID_PARAMETER.into());
    }
    let bytes = if source.length == 0 {
        Vec::new()
    } else {
        read(engine, source.buffer, source.length.into())?
    };
    let plan = match rtl::duplicate(flags, source, &bytes) {
        Ok(plan) => plan,
        Err(_) => {
            record(engine, "duplicate", source, rtl::STATUS_INVALID_PARAMETER);
            return Ok(rtl::STATUS_INVALID_PARAMETER.into());
        }
    };
    if plan.payload.is_empty() {
        let zero = Counted::zero();
        let encoded = zero.encode(engine.get_data().architecture)?;
        write_effect(engine, args[2], &encoded)?;
        record(engine, "duplicate", zero, 0);
        return Ok(0);
    }
    if engine.get_data().apis.kernel_rtl.lifetime_allocations >= OWNED_LIMIT {
        record(engine, "duplicate", source, rtl::STATUS_NO_MEMORY);
        return Ok(rtl::STATUS_NO_MEMORY.into());
    }
    let state = &engine.get_data().apis;
    let candidate = state.pool.prepare(
        &state.memory,
        engine.get_data().architecture,
        0x102,
        plan.payload.len() as u64,
        USTR,
        irql,
    )?;
    let Some(candidate) = candidate else {
        record(engine, "duplicate", source, rtl::STATUS_NO_MEMORY);
        return Ok(rtl::STATUS_NO_MEMORY.into());
    };
    let mut memory = state.memory.clone();
    memory.map(
        candidate.base,
        candidate.mapped,
        candidate.permissions(),
        None,
        "kernel RTL paged Pool candidate",
    )?;
    // Existing Pool performs actual map/init and commits the sole allocation.
    // Everything that could ordinarily reject input is validated before here.
    let allocated = pool::call(
        engine,
        Model::PoolTagged,
        &[1, plan.payload.len() as u64, USTR.into()],
    );
    let address = effect(engine, allocated)?;
    if address != candidate.base {
        engine.get_data_mut().apis.kernel_rtl.native_failure = true;
        bail!("Kernel RTL Pool candidate changed before publication");
    }
    let ordinal = engine.get_data().apis.pool.total_allocations;
    let state = &mut engine.get_data_mut().apis.kernel_rtl;
    state.lifetime_allocations += 1;
    state.owned.insert(
        address,
        Owned {
            base: address,
            requested: plan.payload.len() as u64,
            allocation_ordinal: ordinal,
            live: true,
            initialized: false,
        },
    );
    write_effect(engine, address, &plan.payload)?;
    let output = Counted {
        length: plan.length,
        maximum: plan.maximum,
        buffer: address,
    };
    let encoded = output.encode(engine.get_data().architecture)?;
    write_effect(engine, args[2], &encoded)?;
    engine
        .get_data_mut()
        .apis
        .kernel_rtl
        .owned
        .get_mut(&address)
        .unwrap()
        .initialized = true;
    record(engine, "duplicate", output, 0);
    Ok(0)
}
/// Called after any actual existing Pool free commits. Provenance is retired
/// regardless of tag spelling; tag alone never authorizes string ownership.
pub(super) fn retire_pool(
    engine: &mut Unicorn<Trace>,
    allocation: &emumee_core::pool::Allocation,
) -> Result<()> {
    let state = &mut engine.get_data_mut().apis.kernel_rtl;
    if let Some(record) = state.owned.get_mut(&allocation.base) {
        if record.live {
            if record.requested != allocation.requested {
                state.native_failure = true;
                bail!("Kernel RTL owned Pool allocation diverged before retirement");
            }
            record.live = false;
        }
    }
    Ok(())
}
fn free(engine: &mut Unicorn<Trace>, args: &[u64], irql: u8) -> Result<u64> {
    ensure!(
        irql <= 1,
        "Kernel RTL paged Unicode release requires IRQL<=APC_LEVEL"
    );
    let value = descriptor(engine, args[0])?;
    value.validate()?;
    let zero = Counted::zero().encode(engine.get_data().architecture)?;
    require(engine, args[0], zero.len() as u64, P::WRITE)?;
    if value.buffer == 0 {
        ensure!(
            value.length == 0 && value.maximum == 0,
            "Kernel RTL null buffer descriptor is not empty"
        );
        write_effect(engine, args[0], &zero)?;
        record(engine, "free", value, 0);
        return Ok(0);
    }
    let state = &engine.get_data().apis;
    let owned=state.kernel_rtl.owned.get(&value.buffer).filter(|o|o.live && o.initialized).ok_or_else(||anyhow::anyhow!("Kernel RTL free requires an actual live owned duplicate buffer; borrowed/interior/unknown/retired profile unsupported"))?;
    let allocation = state.pool.prepare_free(value.buffer, None, irql)?.clone();
    ensure!(
        allocation.requested == owned.requested
            && allocation.tag == USTR
            && allocation.paged
            && u64::from(value.maximum) <= allocation.requested,
        "Kernel RTL descriptor/owned Pool allocation profile diverged"
    );
    let end = args[0]
        .checked_add(zero.len() as u64)
        .ok_or_else(|| anyhow::anyhow!("Kernel RTL descriptor output overflow"))?;
    ensure!(
        end <= allocation.base || args[0] >= allocation.base + allocation.mapped,
        "Kernel RTL descriptor overlaps storage being released"
    );
    mdl::require_pool_release(engine, allocation.base, allocation.mapped)?;
    rundown::require_pool_release(engine, allocation.base, allocation.mapped)?;
    let released = pool::call(engine, Model::PoolFree, &[value.buffer]);
    effect(engine, released)?;
    ensure!(
        !engine.get_data().apis.kernel_rtl.owned[&value.buffer].live,
        "Kernel RTL Pool retirement hook was not applied"
    );
    write_effect(engine, args[0], &zero)?;
    record(engine, "free", value, 0);
    Ok(0)
}
fn capture_format(engine: &mut Unicorn<Trace>, args: &[u64], name: &'static str, result: u64) {
    let state = &mut engine.get_data_mut().apis.kernel_rtl;
    if state.formats.len() >= 128 {
        state.formats_omitted = state.formats_omitted.saturating_add(1);
        return;
    }
    let result = result as u32 as i32;
    let wanted = if result < 0 {
        args[1]
    } else {
        args[1].min(result as u64)
    };
    let units = wanted.min(1024) as usize;
    let captured = (|| -> Result<FormatObservation> {
        let raw = read(engine, args[0], units as u64 * 2)?;
        let all = raw
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect::<Vec<_>>();
        let until = all.iter().position(|x| *x == 0).unwrap_or(all.len());
        Ok(FormatObservation {
            api: name,
            buffer: args[0],
            format_address: args[2],
            result,
            captured_units: units,
            text: String::from_utf16_lossy(&all[..until]),
            raw_utf16_sha256: format!("{:x}", Sha256::digest(&raw)),
            truncated: result < 0 || wanted > units as u64,
        })
    })();
    let state = &mut engine.get_data_mut().apis.kernel_rtl;
    match captured {
        Ok(item) => state.formats.push(item),
        Err(_) => state.capture_errors = state.capture_errors.saturating_add(1),
    }
}
pub(super) fn require_native_ready(engine: &Unicorn<Trace>) -> Result<()> {
    ensure!(
        !engine.get_data().apis.kernel_rtl.native_failure,
        "Kernel RTL native effect failed; execution cannot resume"
    );
    Ok(())
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    require_native_ready(engine)?;
    let irql = super::kernel_sync::observe_irql(engine)?;
    engine.get_data_mut().apis.kernel_rtl.active_irql = Some(irql);
    let result = (|| match call {
        Call::Time(call) => kernel_time::invoke(engine, call, args),
        Call::Init => init(engine, args),
        Call::Duplicate => duplicate(engine, args, irql),
        Call::Free => free(engine, args, irql),
        Call::Crt(call) => crt::invoke(engine, args, call),
        Call::Format(call, name) => {
            let result = crt_format::invoke(engine, args, call)?;
            capture_format(engine, args, name, result);
            Ok(result)
        }
    })();
    engine.get_data_mut().apis.kernel_rtl.active_irql = None;
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    fn engine(arch: Architecture) -> crate::NativeEngine {
        let mut engine = crate::new_engine(arch).unwrap();
        engine.get_data_mut().apis.target(arch, true).unwrap();
        crate::kernel_cpu::initialize(&mut engine).unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(0x10000, 8192, P::RW, Some(4), "kernel RTL source tests")
            .unwrap();
        engine
            .mem_map(0x10000, 8192, Prot::READ | Prot::WRITE)
            .unwrap();
        engine.get_data_mut().apis.last_error = 0x12345678;
        engine
    }
    fn source(engine: &mut Unicorn<Trace>, data: &[u8]) {
        engine.mem_write(0x10200, data).unwrap();
        let desc = Counted {
            length: data.len() as u16,
            maximum: data.len() as u16,
            buffer: 0x10200,
        };
        engine
            .mem_write(
                0x10000,
                &desc.encode(engine.get_data().architecture).unwrap(),
            )
            .unwrap();
        engine.mem_write(0x10040, &[0x77; 16]).unwrap();
    }
    #[test]
    fn exact_ntos_allowlist_exposes_only_real_existing_crt_and_typed_unicode_contracts() {
        for (name, count, cc, returns) in [
            ("wcslen", 1, C::Cdecl, T::Pointer),
            ("strnlen", 2, C::Cdecl, T::Pointer),
            ("strchr", 2, C::Cdecl, T::Pointer),
            ("swprintf_s", 3, C::Cdecl, T::U32),
            ("_vsnwprintf", 4, C::Cdecl, T::U32),
            ("RtlInitUnicodeString", 2, C::Stdcall, T::Void),
            ("RtlDuplicateUnicodeString", 3, C::Stdcall, T::U32),
            ("RtlFreeUnicodeString", 1, C::Stdcall, T::Void),
        ] {
            let (_, actual_count, actual_cc, actual_ret) = definition(name).unwrap();
            assert_eq!((actual_count, actual_cc, actual_ret), (count, cc, returns));
            for arch in [Architecture::X86, Architecture::X64] {
                let binding = super::super::definition(arch, "ntoskrnl.exe", name);
                assert!(
                    matches!(binding.model, Model::KernelRtl(_)),
                    "{arch:?} {name}"
                );
                assert_eq!(
                    (binding.count, binding.convention, binding.returns),
                    (count, cc, returns)
                );
                for module in ["hal.dll", "cng.sys", "msvcrt.dll", "ntdll.dll"] {
                    assert!(
                        !matches!(
                            super::super::definition(arch, module, name).model,
                            Model::KernelRtl(_)
                        ),
                        "{arch:?} {module}/{name}"
                    );
                }
            }
        }
        for name in [
            "RtlPrefixUnicodeString",
            "RtlMultiByteToUnicodeN",
            "strcpy_s",
            "strncpy_s",
            "wcscpy_s",
            "wcscat_s",
            "_snprintf_s",
            "DbgPrintEx",
            "RtlPcToFileHeader",
            "strlen",
            "__chkstk",
        ] {
            assert!(definition(name).is_none(), "{name}");
        }
    }
    #[test]
    fn actual_pool_duplicate_raw_bytes_free_zeroes_and_borrowed_or_stale_frees_do_not_succeed() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(arch);
            source(&mut engine, &[0, 0, 0, 0xd8, 0x42, 0]);
            assert_eq!(
                invoke(&mut engine, Call::Duplicate, &[1, 0x10000, 0x10040]).unwrap(),
                0
            );
            let owned = descriptor(&engine, 0x10040).unwrap();
            assert_eq!((owned.length, owned.maximum), (6, 8));
            assert_eq!(
                engine.mem_read_as_vec(owned.buffer, 8).unwrap(),
                [0, 0, 0, 0xd8, 0x42, 0, 0, 0]
            );
            assert_eq!(engine.get_data().apis.pool.total_allocations, 1);
            assert_eq!(report(&engine).live_allocations, 1);
            if arch == Architecture::X64 {
                assert!(owned.buffer > u32::MAX as u64);
            }
            let encoded = owned.encode(arch).unwrap();
            engine.mem_write(0x10080, &encoded).unwrap();
            invoke(&mut engine, Call::Free, &[0x10040]).unwrap();
            assert_eq!(descriptor(&engine, 0x10040).unwrap(), Counted::zero());
            assert!(
                !engine
                    .get_data()
                    .apis
                    .memory
                    .allows(owned.buffer, 1, P::READ)
            );
            assert_eq!(engine.get_data().apis.pool.total_frees, 1);
            assert_eq!(report(&engine).live_allocations, 0);
            invoke(&mut engine, Call::Free, &[0x10040]).unwrap();
            assert_eq!(engine.get_data().apis.pool.total_frees, 1);
            assert!(
                invoke(&mut engine, Call::Free, &[0x10080])
                    .unwrap_err()
                    .to_string()
                    .contains("actual live owned")
            );
            engine.mem_write(0x10200, &[0, 0xd8, 0, 0]).unwrap();
            invoke(&mut engine, Call::Init, &[0x10040, 0x10200]).unwrap();
            assert_eq!(
                descriptor(&engine, 0x10040).unwrap(),
                Counted {
                    length: 2,
                    maximum: 4,
                    buffer: 0x10200
                }
            );
            assert!(invoke(&mut engine, Call::Free, &[0x10040]).is_err());
            assert_eq!(engine.mem_read_as_vec(0x10200, 4).unwrap(), [0, 0xd8, 0, 0]);
            assert_eq!(engine.get_data().apis.last_error, 0x12345678);
        }
    }
    #[test]
    fn generic_pool_release_retires_real_provenance_and_same_tag_reuse_cannot_authorize_free() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(arch);
            source(&mut engine, b"R\0");
            invoke(&mut engine, Call::Duplicate, &[0, 0x10000, 0x10040]).unwrap();
            let owned = descriptor(&engine, 0x10040).unwrap();
            pool::call(
                &mut engine,
                Model::PoolFreeTagged,
                &[owned.buffer, USTR.into()],
            )
            .unwrap();
            assert!(!engine.get_data().apis.kernel_rtl.owned[&owned.buffer].live);
            let other = pool::call(&mut engine, Model::PoolTagged, &[1, 2, USTR.into()]).unwrap();
            assert_eq!(other, owned.buffer);
            assert!(invoke(&mut engine, Call::Free, &[0x10040]).is_err());
            assert!(engine.get_data().apis.pool.allocations.contains_key(&other));
            assert_eq!(engine.get_data().apis.pool.total_frees, 1);
            pool::call(&mut engine, Model::PoolFreeTagged, &[other, USTR.into()]).unwrap();
            invoke(&mut engine, Call::Duplicate, &[0, 0x10000, 0x10080]).unwrap();
            let current = descriptor(&engine, 0x10080).unwrap();
            assert_eq!(current.buffer, owned.buffer);
            // A fresh genuine RTL allocation is current authority. An old equal
            // raw pointer value cannot carry a hidden generation token.
            invoke(&mut engine, Call::Free, &[0x10040]).unwrap();
            assert_eq!(engine.get_data().apis.pool.total_frees, 3);
            assert_eq!(descriptor(&engine, 0x10040).unwrap(), Counted::zero());
            assert!(!engine.get_data().apis.kernel_rtl.owned[&current.buffer].live);
            assert_eq!(
                engine.get_data().apis.kernel_rtl.owned[&current.buffer].allocation_ordinal,
                3
            );
        }
    }
    #[test]
    fn descriptor_preflight_invalid_flags_and_bounded_quota_never_allocate_or_change_output() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(arch);
            source(&mut engine, b"R\0");
            assert_eq!(
                invoke(&mut engine, Call::Duplicate, &[2, 0, 0]).unwrap(),
                u64::from(rtl::STATUS_INVALID_PARAMETER)
            );
            assert!(invoke(&mut engine, Call::Duplicate, &[1, 0x10000, 0x12000]).is_err());
            assert_eq!(engine.get_data().apis.pool.total_allocations, 0);
            engine.get_data_mut().apis.kernel_rtl.lifetime_allocations = OWNED_LIMIT;
            assert_eq!(
                invoke(&mut engine, Call::Duplicate, &[1, 0x10000, 0x10040]).unwrap(),
                u64::from(rtl::STATUS_NO_MEMORY)
            );
            assert_eq!(engine.mem_read_as_vec(0x10040, 16).unwrap(), [0x77; 16]);
            assert_eq!(engine.get_data().apis.pool.total_allocations, 0);
            assert_eq!(engine.get_data().apis.last_error, 0x12345678);
        }
    }
    #[test]
    fn crt_aliases_count_raw_units_search_nul_lowbyte_and_keep_full_guest_pointers() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(arch);
            let bounded = Call::Crt(crt::Call::Length {
                wide: false,
                bounded: true,
            });
            assert_eq!(invoke(&mut engine, bounded, &[0, 0]).unwrap(), 0);
            engine.mem_write(0x10380, b"abc\0z").unwrap();
            assert_eq!(invoke(&mut engine, bounded, &[0x10380, 2]).unwrap(), 2);
            assert_eq!(invoke(&mut engine, bounded, &[0x10380, 5]).unwrap(), 3);
            assert_eq!(invoke(&mut engine, bounded, &[0x10380, 0]).unwrap(), 0);
            engine
                .mem_write(0x10200, &[0x3d, 0xd8, 0, 0xde, 0, 0xd8, 0, 0])
                .unwrap();
            assert_eq!(
                invoke(
                    &mut engine,
                    Call::Crt(crt::Call::Length {
                        wide: true,
                        bounded: false
                    }),
                    &[0x10200]
                )
                .unwrap(),
                3
            );
            engine.mem_write(0x10300, &[0x41, 0xff, 0, 0x42]).unwrap();
            let call = Call::Crt(crt::Call::StringFind {
                wide: false,
                reverse: false,
            });
            assert_eq!(
                invoke(&mut engine, call, &[0x10300, u64::MAX]).unwrap(),
                0x10301
            );
            assert_eq!(invoke(&mut engine, call, &[0x10300, 0]).unwrap(), 0x10302);
            assert_eq!(invoke(&mut engine, call, &[0x10300, 0x42]).unwrap(), 0);
            assert_eq!(engine.get_data().apis.last_error, 0x12345678);
        }
    }
    #[test]
    fn actual_paged_access_and_native_effect_failures_never_resume_or_publish_fake_success() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(arch);
            source(&mut engine, b"R\0");
            invoke(&mut engine, Call::Duplicate, &[1, 0x10000, 0x10040]).unwrap();
            let owned = descriptor(&engine, 0x10040).unwrap();
            if arch == Architecture::X64 {
                engine.reg_write(RegisterX86::CR8, 2).unwrap();
            } else {
                let pcr = crate::kernel_cpu::current_pcr(&engine).unwrap();
                engine.mem_write(pcr + 0x24, &[2]).unwrap();
            }
            assert!(
                invoke(
                    &mut engine,
                    Call::Crt(crt::Call::Length {
                        wide: true,
                        bounded: false
                    }),
                    &[owned.buffer]
                )
                .unwrap_err()
                .to_string()
                .contains("paged Pool access")
            );
            assert!(invoke(&mut engine, Call::Free, &[0x10040]).is_err());
            assert_eq!(report(&engine).live_allocations, 1);
            let failed = write_effect(&mut engine, 0x20000, &[1]);
            assert!(failed.is_err());
            assert!(completion_error(&engine).is_some());
            assert!(
                invoke(&mut engine, Call::Init, &[0x10040, 0])
                    .unwrap_err()
                    .to_string()
                    .contains("cannot resume")
            );
        }
    }
    #[test]
    fn existing_formatter_native_output_failure_sets_terminal_rtl_state_without_capture_success() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(arch);
            engine
                .mem_write(0x10200, &[b'%', 0, b'd', 0, 0, 0])
                .unwrap();
            engine
                .get_data_mut()
                .apis
                .memory
                .map(
                    0x20000,
                    4096,
                    P::RW,
                    Some(4),
                    "RTL native failure model-only output",
                )
                .unwrap();
            if arch == Architecture::X64 {
                engine.reg_write(RegisterX86::R9, 42).unwrap();
            } else {
                engine.reg_write(RegisterX86::ESP, 0x11000).unwrap();
                engine.mem_write(0x11010, &42u32.to_le_bytes()).unwrap();
            }
            assert!(
                invoke(
                    &mut engine,
                    Call::Format(crt_format::Call::Secure(false), "swprintf_s"),
                    &[0x20000, 8, 0x10200]
                )
                .is_err()
            );
            let report = report(&engine);
            assert!(report.native_effect_failure);
            assert!(report.formatting.is_empty());
            assert_eq!(report.capture_errors, 0);
            assert!(completion_error(&engine).is_some());
        }
    }
}
