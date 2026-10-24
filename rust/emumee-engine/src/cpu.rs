//! Bounded instruction-page classification, invalidated by guest and model writes.
//! Ordinary instructions use one page comparison and one byte lookup.
use super::*;
use anyhow::bail;
use emumee_core::cpu::CpuProfile;
use std::collections::BTreeMap;
const PAGE: usize = 4096;
const MAX_PAGES: usize = 256;
const CPUID: u8 = 1;
const RDTSC: u8 = 2;
const RDTSCP: u8 = 3;
const XGETBV: u8 = 4;
const SYSCALL: u8 = 5;
const SYSRET: u8 = 6;
const SYSENTER: u8 = 7;
const SYSEXIT: u8 = 8;
const WRMSR: u8 = 9;
const RDMSR: u8 = 10;
const CONTROL_WRITE: u8 = 11;
const CONTROL_READ: u8 = 12;
mod cpuid_receipts;
mod cr8;
pub(crate) mod debug_control;
mod msr_faults;
pub(crate) mod native_reads;

struct Page {
    base: u64,
    instructions: Box<[u8; PAGE]>,
    // Zero is unknown; otherwise (instruction size << 1) | forbidden.
    // Kept on the same page object so every CPU cache invalidation also drops
    // DPC decisions, including writes up to 14 bytes into the next page.
    dpc_forbidden: Box<[u8; PAGE]>,
}
#[derive(Default)]
pub(crate) struct InstructionCache {
    current: Option<Page>,
    other: BTreeMap<u64, Page>,
}
impl InstructionCache {
    #[inline]
    fn lookup(&self, pc: u64) -> Option<u8> {
        self.current
            .as_ref()
            .filter(|page| page.base == pc & !4095)
            .map(|page| page.instructions[(pc & 4095) as usize])
    }
    #[inline]
    pub(crate) fn dpc_lookup(&self, pc: u64, size: u32) -> Option<bool> {
        if !(1..=15).contains(&size) {
            return None;
        }
        let base = pc & !4095;
        let page = self
            .current
            .as_ref()
            .filter(|page| page.base == base)
            .or_else(|| self.other.get(&base))?;
        let value = page.dpc_forbidden[(pc & 4095) as usize];
        (value >> 1 == size as u8).then_some(value & 1 != 0)
    }
    #[inline]
    pub(crate) fn dpc_store(&mut self, pc: u64, size: u32, forbidden: bool) {
        if !(1..=15).contains(&size) {
            return;
        }
        let base = pc & !4095;
        let page = match self.current.as_mut().filter(|page| page.base == base) {
            Some(page) => page,
            None => match self.other.get_mut(&base) {
                Some(page) => page,
                None => return, // First hit may precede CPU page classification.
            },
        };
        page.dpc_forbidden[(pc & 4095) as usize] = ((size as u8) << 1) | u8::from(forbidden);
    }
    pub fn invalidate(&mut self, address: u64, size: usize) {
        if size == 0 {
            return;
        }
        // A changed byte may belong to a prefixed instruction in the prior page.
        let first = address.saturating_sub(14) & !4095;
        let last = address.saturating_add(size as u64 - 1) & !4095;
        if self
            .current
            .as_ref()
            .is_some_and(|page| (first..=last).contains(&page.base))
        {
            self.current = None;
        }
        while let Some((&base, _)) = self.other.range(first..=last).next() {
            self.other.remove(&base);
        }
    }
    fn select(&mut self, page: Page) {
        if let Some(previous) = self.current.replace(page) {
            self.other.insert(previous.base, previous);
        }
        // Bounded deterministic eviction. It is not touched on the hot path.
        if self.other.len() >= MAX_PAGES {
            self.other.pop_first();
        }
    }
}
#[derive(Default, Debug, Serialize)]
pub struct CpuReport {
    pub cpuid: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuid_receipts: Option<cpuid_receipts::Report>,
    pub rdtsc: u64,
    pub rdtscp: u64,
    pub xgetbv: u64,
    pub tsc_msr_reads: u64,
    pub tsc_msr_writes: u64,
    pub cr8_reads: u64,
    pub cr8_writes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_control: Option<debug_control::Report>,
}
#[derive(Default)]
pub(crate) struct CpuState {
    pub profile: CpuProfile,
    pub processor: u32,
    pub report: CpuReport,
    pub cache: InstructionCache,
    pub fault: Option<String>,
    pub tsc_offset: u64,
    pub tsc_adjust: u64,
    pub native_reads: native_reads::State,
    pub debug_control: debug_control::State,
    watched: BTreeMap<u64, u64>,
    watch_count: usize,
}
impl CpuState {
    pub(crate) fn configured(profile: CpuProfile) -> Self {
        Self {
            profile,
            ..Self::default()
        }
    }
}
/// Watch writable executable allocations. RX pages cannot change through guest
/// stores, and protection changes/model writes independently invalidate the cache.
/// The preceding page covers native accesses that straddle the allocation edge.
pub(crate) fn watch(engine: &mut Unicorn<Trace>, base: u64, size: u64) -> Result<()> {
    let first = base.saturating_sub(4096);
    let last = base
        .checked_add(size)
        .and_then(|end| end.checked_sub(1))
        .ok_or_else(|| anyhow!("Code watch range overflow"))?;
    if engine
        .get_data()
        .cpu
        .watched
        .range(..=first)
        .next_back()
        .is_some_and(|(_, end)| *end >= last)
    {
        return Ok(());
    }
    ensure!(
        engine.get_data().cpu.watch_count < 8192,
        "Executable write-watch bound exceeded"
    );
    uc(engine.add_mem_hook(
        HookType::MEM_WRITE,
        first,
        last,
        |engine, _, address, size, _| {
            engine.get_data_mut().cpu.cache.invalidate(address, size);
            true
        },
    ))?;
    engine.get_data_mut().cpu.watched.insert(first, last);
    engine.get_data_mut().cpu.watch_count += 1;
    Ok(())
}
fn classify(bytes: &[u8], wide: bool) -> u8 {
    let mut at = 0;
    while at < bytes.len().min(13)
        && (matches!(
            bytes[at],
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf2 | 0xf3
        ) || (wide && (0x40..=0x4f).contains(&bytes[at])))
    {
        at += 1;
    }
    let rest = &bytes[at..];
    let (kind, len) = if rest.starts_with(&[0x0f, 0xa2]) {
        (CPUID, 2)
    } else if rest.starts_with(&[0x0f, 0x31]) {
        (RDTSC, 2)
    } else if rest.starts_with(&[0x0f, 0x01, 0xf9]) {
        (RDTSCP, 3)
    } else if rest.starts_with(&[0x0f, 0x01, 0xd0]) {
        (XGETBV, 3)
    } else if rest.starts_with(&[0x0f, 0x05]) {
        (SYSCALL, 2)
    } else if rest.starts_with(&[0x0f, 0x07]) {
        (SYSRET, 2)
    } else if rest.starts_with(&[0x0f, 0x34]) {
        (SYSENTER, 2)
    } else if rest.starts_with(&[0x0f, 0x35]) {
        (SYSEXIT, 2)
    } else if rest.starts_with(&[0x0f, 0x30]) {
        (WRMSR, 2)
    } else if rest.starts_with(&[0x0f, 0x32]) {
        (RDMSR, 2)
    } else if rest.starts_with(&[0x0f, 0x20]) {
        return CONTROL_READ << 4;
    } else if rest.starts_with(&[0x0f, 0x22])
        || rest.starts_with(&[0x0f, 0x06])
        || rest.starts_with(&[0x0f, 0x01, 0xd1])
        || rest.len() >= 3
            && rest[0] == 0x0f
            && ((rest[1] == 0x01 && matches!((rest[2] >> 3) & 7, 2 | 3 | 6))
                || (rest[1] == 0x00 && matches!((rest[2] >> 3) & 7, 2 | 3)))
    {
        // Memory operands have variable native-decoded lengths. Zero is an
        // explicit control-write sentinel, not an invented instruction size.
        return CONTROL_WRITE << 4;
    } else {
        return 0;
    };
    if at + len > 15 {
        return 0;
    }
    kind << 4 | (at + len) as u8
}
fn classify_page(engine: &Unicorn<Trace>, base: u64) -> Result<Page> {
    let mut bytes = [0u8; PAGE + 14];
    uc(engine.mem_read(base, &mut bytes[..PAGE]))?;
    let mut end = PAGE;
    // The following page may be absent. Do not require it for a valid page.
    if let Some(next) = base.checked_add(PAGE as u64) {
        for byte in &mut bytes[PAGE..] {
            if engine
                .mem_read(next + (end - PAGE) as u64, std::slice::from_mut(byte))
                .is_err()
            {
                break;
            }
            end += 1;
        }
    }
    let wide = engine.get_data().architecture == Architecture::X64;
    let mut instructions = Box::new([0; PAGE]);
    for (at, value) in instructions.iter_mut().enumerate() {
        *value = classify(&bytes[at..end.min(at + 15)], wide);
    }
    Ok(Page {
        base,
        instructions,
        dpc_forbidden: Box::new([0; PAGE]),
    })
}
fn instruction(engine: &mut Unicorn<Trace>, pc: u64) -> Result<u8> {
    if let Some(value) = engine.get_data().cpu.cache.lookup(pc) {
        return Ok(value);
    }
    let base = pc & !4095;
    let page = if let Some(page) = engine.get_data_mut().cpu.cache.other.remove(&base) {
        page
    } else {
        classify_page(engine, base)?
    };
    engine.get_data_mut().cpu.cache.select(page);
    Ok(engine.get_data().cpu.cache.lookup(pc).unwrap())
}
/// Host-side writes bypass Unicorn's guest memory hooks. All model writes use this.
pub(crate) fn write(engine: &mut Unicorn<Trace>, address: u64, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    crate::api::kernel_spin::require_write(engine, address, bytes.len() as u64)?;
    crate::threads::timers::require_write(engine, address, bytes.len() as u64)?;
    crate::threads::dpc::require_api_access(
        engine,
        address,
        bytes.len() as u64,
        Permissions::WRITE,
    )?;
    crate::ipi::require_api_access(
        engine,
        address,
        bytes.len() as u64,
        emumee_core::memory::Permissions::WRITE,
    )?;
    crate::api::provider_metadata::require_api_access(
        engine,
        address,
        bytes.len() as u64,
        Permissions::WRITE,
    )?;
    crate::api::reference_mapping::require_api_access(
        engine,
        address,
        bytes.len() as u64,
        Permissions::WRITE,
    )?;
    crate::kernel_loader::require_host_write(engine, address, bytes.len() as u64)?;
    crate::api::mdl::require_api_write(engine, address, bytes.len() as u64)?;
    crate::api::callbacks::require_api_access(
        engine,
        address,
        bytes.len() as u64,
        emumee_core::memory::Permissions::WRITE,
    )?;
    crate::api::rundown::require_api_access(
        engine,
        address,
        bytes.len() as u64,
        emumee_core::memory::Permissions::WRITE,
    )?;
    crate::api::kernel_environment::require_api_access(
        engine,
        address,
        bytes.len() as u64,
        emumee_core::memory::Permissions::WRITE,
    )?;
    crate::api::kernel_objects::require_api_access(
        engine,
        address,
        bytes.len() as u64,
        emumee_core::memory::Permissions::WRITE,
    )?;
    crate::api::kernel_thread_objects::require_api_access(
        engine,
        address,
        bytes.len() as u64,
        emumee_core::memory::Permissions::WRITE,
    )?;
    let end = address
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| anyhow!("Model memory write range overflow"))?;
    engine
        .get_data_mut()
        .cpu
        .cache
        .invalidate(address, bytes.len());
    let written = engine.mem_write(address, bytes);
    crate::kernel_stack_writes::model_write(engine, address, bytes.len(), written.is_ok());
    crate::image_writes::model_write(engine, address, bytes.len(), written.is_ok());
    crate::instruction_window::model_write(engine, address, bytes, written.is_ok());
    uc(written)?;
    // Clearing our decoder classifications is insufficient: already executed
    // guest bytes can still reside in Unicorn's translated-block cache. Model
    // writes bypass guest store hooks, so invalidate that cache after the write
    // as well. The backend requires an exclusive end greater than the start.
    uc(engine.ctl_remove_cache(address, end))
}
pub(crate) fn observe(engine: &mut Unicorn<Trace>, pc: u64, size: u32) -> Result<()> {
    let instruction = instruction(engine, pc)?;
    if instruction == 0
        || !matches!(instruction >> 4, CONTROL_WRITE | CONTROL_READ)
            && (instruction & 15) as u32 != size
    {
        return Ok(());
    }
    ensure!(
        !crate::threads::dpc::active(engine)
            || !matches!(
                instruction >> 4,
                CONTROL_WRITE | WRMSR | SYSCALL | SYSRET | SYSENTER | SYSEXIT
            ),
        "DPC architectural processor mutation is unsupported"
    );
    let wide = engine.get_data().architecture == Architecture::X64;
    let registers = if wide {
        [
            RegisterX86::RAX,
            RegisterX86::RBX,
            RegisterX86::RCX,
            RegisterX86::RDX,
        ]
    } else {
        [
            RegisterX86::EAX,
            RegisterX86::EBX,
            RegisterX86::ECX,
            RegisterX86::EDX,
        ]
    };
    match instruction >> 4 {
        CONTROL_WRITE | CONTROL_READ => {
            if cr8::observe(engine, pc, size)? {
                return Ok(());
            }
            if instruction >> 4 == CONTROL_READ {
                native_reads::arm_control(engine, pc, size);
                return Ok(());
            }
            if !crate::ipi::member_running(engine) {
                return Ok(());
            }
            bail!("IPI non-MSR processor control mutation is not modeled");
        }
        WRMSR | RDMSR => {
            let index = uc(engine.reg_read(registers[2]))? as u32;
            if debug_control::msr(engine, pc, size, index, instruction >> 4 == WRMSR)? {
                return Ok(());
            }
            ensure!(
                !crate::ipi::member_running(engine)
                    || crate::kernel_cpu::ipi_processors::owns_msr(index),
                "IPI MSR ownership is not modeled for this register"
            );
            if msr_faults::before(engine, pc, size, index, instruction >> 4 == WRMSR)? {
                return Ok(());
            }
            if !matches!(index, 0x10 | 0x3b) {
                return if instruction >> 4 == WRMSR {
                    crate::kernel_cpu::before_msr_write(engine)
                } else {
                    native_reads::arm_msr(engine, pc, size, index);
                    Ok(())
                };
            }
            ensure!(
                engine.get_data().apis.kernel_mode
                    && uc(engine.reg_read(RegisterX86::CS))? & 3 == 0,
                "TSC MSR access requires a CPL0 driver context"
            );
            engine.get_data_mut().clock.flush_cycles()?;
            let base = engine.get_data().clock.tsc();
            if instruction >> 4 == WRMSR {
                let value = (uc(engine.reg_read(registers[0]))? as u32 as u64)
                    | ((uc(engine.reg_read(registers[3]))? as u32 as u64) << 32);
                let cpu = &mut engine.get_data_mut().cpu;
                if index == 0x10 {
                    let offset = value.wrapping_sub(base);
                    cpu.tsc_adjust = cpu
                        .tsc_adjust
                        .wrapping_add(offset.wrapping_sub(cpu.tsc_offset));
                    cpu.tsc_offset = offset;
                } else {
                    cpu.tsc_offset = cpu
                        .tsc_offset
                        .wrapping_add(value.wrapping_sub(cpu.tsc_adjust));
                    cpu.tsc_adjust = value;
                }
                cpu.report.tsc_msr_writes += 1;
            } else {
                let value = if index == 0x10 {
                    base.wrapping_add(engine.get_data().cpu.tsc_offset)
                } else {
                    engine.get_data().cpu.tsc_adjust
                };
                uc(engine.reg_write(registers[0], value as u32 as u64))?;
                uc(engine.reg_write(registers[3], value >> 32))?;
                engine.get_data_mut().cpu.report.tsc_msr_reads += 1;
            }
        }
        SYSCALL | SYSRET | SYSENTER | SYSEXIT => {
            return crate::kernel_cpu::system_entry(
                engine,
                pc,
                size,
                match instruction >> 4 {
                    SYSCALL => "SYSCALL",
                    SYSRET => "SYSRET",
                    SYSENTER => "SYSENTER",
                    _ => "SYSEXIT",
                },
            );
        }
        CPUID => {
            let function = uc(engine.reg_read(registers[0]))? as u32;
            let subleaf = uc(engine.reg_read(registers[2]))? as u32;
            let result = engine.get_data().cpu.profile.leaf(
                function,
                subleaf,
                engine.get_data().cpu.processor,
            );
            for (register, value) in registers.into_iter().zip(result) {
                uc(engine.reg_write(register, value as u64))?;
            }
            engine.get_data_mut().cpu.report.cpuid += 1;
            cpuid_receipts::record(engine, pc, function, subleaf, result);
        }
        RDTSC | RDTSCP => {
            engine.get_data_mut().clock.flush_cycles()?;
            let value = engine
                .get_data()
                .clock
                .tsc()
                .wrapping_add(engine.get_data().cpu.tsc_offset);
            uc(engine.reg_write(registers[0], value as u32 as u64))?;
            uc(engine.reg_write(registers[3], value >> 32))?;
            if instruction >> 4 == RDTSCP {
                let aux = crate::kernel_cpu::tsc_aux(engine)?;
                uc(engine.reg_write(registers[2], aux))?;
                engine.get_data_mut().cpu.report.rdtscp += 1;
            } else {
                engine.get_data_mut().cpu.report.rdtsc += 1;
            }
        }
        XGETBV => {
            ensure!(
                uc(engine.reg_read(registers[2]))? as u32 == 0,
                "Unmodeled XGETBV index (guest #GP)"
            );
            uc(engine.reg_write(registers[0], 7))?;
            uc(engine.reg_write(registers[3], 0))?;
            engine.get_data_mut().cpu.report.xgetbv += 1;
        }
        _ => unreachable!(),
    }
    uc(engine.reg_write(
        if wide {
            RegisterX86::RIP
        } else {
            RegisterX86::EIP
        },
        pc + size as u64,
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_handles_prefixes_boundaries_mutation_and_eviction() {
        assert_eq!(classify(&[0x66, 0x0f, 0xa2], false), CPUID << 4 | 3);
        assert_eq!(classify(&[0x48, 0x0f, 0x31], true), RDTSC << 4 | 3);
        assert_eq!(classify(&[0x48, 0x0f, 0x31], false), 0);
        assert_eq!(classify(&[0xf0, 0x0f, 0xa2], true), 0);
        assert_eq!(classify(&[0x66; 15], true), 0);
        let mut cache = InstructionCache::default();
        for index in 0..MAX_PAGES + 10 {
            cache.select(Page {
                base: index as u64 * 4096,
                instructions: Box::new([0; PAGE]),
                dpc_forbidden: Box::new([0; PAGE]),
            });
        }
        assert_eq!(cache.other.len(), MAX_PAGES - 1);
        cache.invalidate((MAX_PAGES as u64 + 9) * 4096 + 5, 1);
        assert!(cache.current.is_none());
        cache.select(Page {
            base: 4096,
            instructions: Box::new([0; PAGE]),
            dpc_forbidden: Box::new([0; PAGE]),
        });
        cache.invalidate(8192, 1);
        assert!(cache.current.is_none()); // Instruction may straddle the boundary.
    }
    #[test]
    fn model_writes_invalidate_cached_instructions() {
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        engine.mem_map(0x1000, 8192, Prot::ALL).unwrap();
        write(&mut engine, 0x1fff, &[0x0f, 0xa2]).unwrap();
        assert_eq!(instruction(&mut engine, 0x1fff).unwrap(), CPUID << 4 | 2);
        write(&mut engine, 0x2000, &[0x31]).unwrap();
        assert_eq!(instruction(&mut engine, 0x1fff).unwrap(), RDTSC << 4 | 2);
        write(&mut engine, 0x1fff, &[0x90]).unwrap();
        assert_eq!(instruction(&mut engine, 0x1fff).unwrap(), 0);
        engine.get_data_mut().cpu.watch_count = 8192;
        assert!(
            watch(&mut engine, 0x4000, 4096)
                .unwrap_err()
                .to_string()
                .contains("bound")
        );
    }
}
