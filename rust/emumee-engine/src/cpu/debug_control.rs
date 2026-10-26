//! Guest-owned per-processor IA32_DEBUGCTL and bounded legacy branch history.
//! LBR MSR data encodings and TF-driven #DB delivery are explicit boundaries.
use super::*;
use emumee_core::debug_control::{DebugControl, Edge, EdgeKind, IA32_DEBUGCTL};

#[derive(Clone, Debug, Serialize)]
struct Pending {
    from: u64,
    fallthrough: u64,
    unconditional: bool,
    thread: u64,
    current_thread: u64,
}
#[derive(Clone, Debug, Serialize)]
struct Processor {
    device: DebugControl,
    reads: u64,
    writes: u64,
    pending: Option<Pending>,
}
#[derive(Default)]
pub(crate) struct State {
    processors: BTreeMap<u32, Processor>,
    active: bool,
}
impl State {
    #[inline]
    pub(crate) fn active(&self) -> bool {
        self.active
    }
}
#[derive(Debug, Serialize)]
pub struct Report {
    processors: BTreeMap<u32, Processor>,
    scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().cpu.debug_control;
    (!state.processors.is_empty()).then(|| Report {
        processors: state.processors.clone(),
        scope: "Configured Intel legacy32 LBR/BTF controls, perCPU reset DEBUGCTL0; committed near taken branches record actual from/to in a bounded32-entry history. Same-owner ordinary quantum checkpoints preserve pending edges and device state without recording an invented scheduler branch. No prediction/cycle metadata or guest LBR MSR encoding is fabricated. Other DEBUGCTL controls, EFLAGS.TF with BTF, far/system/exception transfers, active API dispatch, DPC delivery and actual ownership changes remain explicit unsupported boundaries. Pending edges are attempts, never claimed retired until a next hook in the same owner is observed.",
    })
}
fn depth(engine: &Unicorn<Trace>) -> Result<usize> {
    let cpu = &engine.get_data().cpu;
    let vendor = cpu.profile.leaf(0, 0, cpu.processor);
    let leaf = cpu.profile.leaf(1, 0, cpu.processor);
    let signature = leaf[0];
    let family = (signature >> 8) & 15;
    let model = ((signature >> 4) & 15) | ((signature >> 12) & 0xf0);
    ensure!(
        vendor[1..] == [0x756e6547, 0x6c65746e, 0x49656e69]
            && family == 6
            && matches!(model, 0x8c | 0x8d | 0xa5 | 0xa6),
        "DEBUGCTL processor profile requires verified Intel legacy LBR geometry"
    );
    ensure!(
        cpu.profile.leaf(7, 0, cpu.processor)[3] & (1 << 19) == 0,
        "DEBUGCTL legacy recording requires a non-architectural-LBR profile"
    );
    Ok(32)
}
fn lbr_data(index: u32) -> bool {
    matches!(index,0x1c8|0x1c9|0x1db..=0x1de|0x345|0x680..=0x69f|0x6c0..=0x6df|0xdc0..=0xddf)
}
pub(crate) fn msr(
    engine: &mut Unicorn<Trace>,
    pc: u64,
    size: u32,
    index: u32,
    write: bool,
) -> Result<bool> {
    if lbr_data(index) {
        bail!(
            "Legacy LBR data/selection MSR {index:#x} format and prediction metadata are not modeled"
        );
    }
    if index != IA32_DEBUGCTL {
        return Ok(false);
    }
    ensure!(
        engine.get_data().architecture == Architecture::X64
            && engine.get_data().apis.kernel_mode
            && uc(engine.reg_read(RegisterX86::CS))? & 3 == 0,
        "DEBUGCTL requires an AMD64 CPL0 driver context"
    );
    let depth = depth(engine)?;
    let processor = engine.get_data().cpu.processor;
    let flags = uc(engine.reg_read(RegisterX86::EFLAGS))?;
    let value = if write {
        Some(
            (uc(engine.reg_read(RegisterX86::RAX))? as u32 as u64)
                | ((uc(engine.reg_read(RegisterX86::RDX))? as u32 as u64) << 32),
        )
    } else {
        None
    };
    // Validate a candidate before publishing a new processor device or changing
    // any committed device/register state.
    let mut candidate = engine
        .get_data()
        .cpu
        .debug_control
        .processors
        .get(&processor)
        .cloned()
        .unwrap_or(Processor {
            device: DebugControl::new(depth)?,
            reads: 0,
            writes: 0,
            pending: None,
        });
    if let Some(value) = value {
        candidate.device.write(value, flags & 0x100 != 0)?;
        candidate.writes += 1;
    } else {
        candidate.reads += 1;
    }
    let output = candidate.device.read();
    if !write {
        uc(engine.reg_write(RegisterX86::RAX, output as u32 as u64))?;
        uc(engine.reg_write(RegisterX86::RDX, output >> 32))?;
    }
    uc(engine.reg_write(RegisterX86::RIP, pc + u64::from(size)))?;
    let state = &mut engine.get_data_mut().cpu.debug_control;
    state.processors.insert(processor, candidate);
    state.active = state
        .processors
        .values()
        .any(|p| p.device.read() != 0 || p.pending.is_some());
    Ok(true)
}

// Native decoding already supplied the exact instruction size. This classifier
// only recognizes control-transfer opcodes; it does not guess instruction ends.
fn branch(bytes: &[u8]) -> Result<Option<bool>> {
    let at = bytes
        .iter()
        .position(|b| {
            !matches!(
                b,
                0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf2 | 0xf3 | 0x40..=0x4f
            )
        })
        .context("DEBUGCTL instruction has only prefixes")?;
    let op = bytes[at];
    match op {
        0xe8 | 0xe9 | 0xeb | 0xc2 | 0xc3 => Ok(Some(true)),
        0x70..=0x7f | 0xe0..=0xe3 => Ok(Some(false)),
        0x0f if bytes.get(at + 1).is_some_and(|x| matches!(x, 0x80..=0x8f)) => Ok(Some(false)),
        0xff => match bytes.get(at + 1).map(|x| (x >> 3) & 7) {
            Some(2 | 4) => Ok(Some(true)),
            Some(3 | 5) => {
                bail!("DEBUGCTL far transfers require architectural LBR exception support")
            }
            _ => Ok(None),
        },
        0x9a | 0xea | 0xca | 0xcb | 0xcc | 0xcd | 0xce | 0xcf | 0xf1 | 0xf4 => {
            bail!("DEBUGCTL far/system/exception transfer is not modeled")
        }
        0x0f if bytes
            .get(at + 1)
            .is_some_and(|x| matches!(x, 0x05 | 0x07 | 0x34 | 0x35 | 0x0b)) =>
        {
            bail!("DEBUGCTL far/system/exception transfer is not modeled")
        }
        _ => Ok(None),
    }
}
pub(crate) fn before_instruction(
    engine: &mut Unicorn<Trace>,
    pc: u64,
    size: u32,
    api_gate: bool,
) -> Result<()> {
    let processor = engine.get_data().cpu.processor;
    let Some(previous) = engine
        .get_data()
        .cpu
        .debug_control
        .processors
        .get(&processor)
    else {
        return Ok(());
    };
    let value = previous.device.read();
    if value == 0 && previous.pending.is_none() {
        return Ok(());
    }
    let thread = crate::threads::current_id(engine);
    let current_thread = crate::threads::thread_address(engine);
    if let Some(pending) = previous.pending.as_ref() {
        ensure!(
            pending.thread == thread && pending.current_thread == current_thread,
            "DEBUGCTL branch completion changed guest owner"
        );
    }
    let stepping = previous
        .device
        .validate_execution(uc(engine.reg_read(RegisterX86::EFLAGS))? & 0x100 != 0);
    // The previous branch reached this exact hook in its original owner. Its
    // retirement precedes any rejection of the current instruction/API.
    let device = engine
        .get_data_mut()
        .cpu
        .debug_control
        .processors
        .get_mut(&processor)
        .unwrap();
    if let Some(pending) = device.pending.take() {
        if pending.unconditional || pc != pending.fallthrough {
            device.device.record_taken(Edge {
                from: pending.from,
                to: pc,
                kind: EdgeKind::Branch,
            });
        }
    }
    // No modeled API effects may occur while hardware tracing needs return,
    // interrupt, or context-switch semantics that have not been implemented.
    ensure!(
        !api_gate,
        "DEBUGCTL active API boundary requires architectural branch-transition support"
    );
    stepping?;
    ensure!(
        !crate::threads::dpc::active(engine),
        "DEBUGCTL DPC exception-transition tracing is not modeled"
    );
    let bytes = uc(engine.mem_read_as_vec(pc, size as usize))?;
    let kind = branch(&bytes)?;
    let device = engine
        .get_data_mut()
        .cpu
        .debug_control
        .processors
        .get_mut(&processor)
        .unwrap();
    if device.device.recording() {
        if let Some(unconditional) = kind {
            device.pending = Some(Pending {
                from: pc,
                fallthrough: pc + u64::from(size),
                unconditional,
                thread,
                current_thread,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::fixtures::counted_driver;
    fn image(code: &[u8]) -> Vec<u8> {
        let mut image = counted_driver(Architecture::X64, 1);
        image[0x200..0x200 + code.len()].copy_from_slice(code);
        image
    }
    fn quantum_image(recording: bool, blocked_child: bool) -> Vec<u8> {
        use emumee_core::fixtures::{ApiFixture, EnvironmentFixture};
        let mut image = emumee_core::fixtures::api_probe(
            Architecture::X64,
            ApiFixture::Environment(EnvironmentFixture::DataOnly),
        );
        image[0x1280..0x12b0].fill(0);
        image[0x1380..0x13b0].fill(0);
        image[0x1500..0x1580].fill(0);
        for (index, name) in ["PsCreateSystemThread", "KeDelayExecutionThread"]
            .into_iter()
            .enumerate()
        {
            let rva = 0x2300u64 + index as u64 * 64;
            for table in [0x1280, 0x1380] {
                image[table + index * 8..table + index * 8 + 8].copy_from_slice(&rva.to_le_bytes());
            }
            let at = 0x1502 + index * 64;
            image[at..at + name.len()].copy_from_slice(name.as_bytes());
        }
        image[0x1d80..0x1da0].fill(0);
        image[0x1d90..0x1d98].copy_from_slice(&(-100_000_000i64).to_le_bytes());
        fn rel(code: &mut Vec<u8>, start: u32, prefix: &[u8], target: u32) {
            code.extend(prefix);
            code.extend((target as i32 - (start as i32 + code.len() as i32 + 4)).to_le_bytes());
        }
        let mut root = vec![0x48, 0x83, 0xec, 0x48];
        rel(&mut root, 0x1000, &[0x48, 0x8d, 0x0d], 0x2b00);
        root.extend([
            0xba, 0xff, 0xff, 0x1f, 0, 0x45, 0x31, 0xc0, 0x45, 0x31, 0xc9,
        ]);
        root.extend([0x48, 0xc7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
        rel(&mut root, 0x1000, &[0x48, 0x8d, 0x05], 0x1800);
        root.extend([0x48, 0x89, 0x44, 0x24, 0x28]);
        rel(&mut root, 0x1000, &[0x48, 0x8d, 0x05], 0x2b80);
        root.extend([0x48, 0x89, 0x44, 0x24, 0x30]);
        rel(&mut root, 0x1000, &[0xff, 0x15], 0x2080);
        let spin = root.len();
        rel(&mut root, 0x1000, &[0x8b, 0x05], 0x2b80);
        root.extend([0x85, 0xc0, 0x74]);
        root.push((spin as isize - (root.len() + 1) as isize) as i8 as u8);
        root.extend([0xb9, 0xd9, 1, 0, 0]);
        write(&mut root, if recording { 3 } else { 0 });
        // Each triplet includes a taken zero-displacement branch. A256-step
        // quantum cycles through every position, including pending branches.
        for _ in 0..300 {
            root.extend([0xeb, 0, 0x90, 0x90]);
        }
        write(&mut root, 0);
        root.extend([0xb8, 42, 0, 0, 0, 0x48, 0x83, 0xc4, 0x48, 0xc3]);
        assert!(root.len() < 0x800);
        image[0x200..0x1200].fill(0xcc);
        image[0x200..0x200 + root.len()].copy_from_slice(&root);
        let mut child = vec![0x48, 0x83, 0xec, 0x28, 0xb8, 1, 0, 0, 0];
        rel(&mut child, 0x1800, &[0x89, 0x05], 0x2b80);
        if blocked_child {
            child.extend([0x31, 0xc9, 0x31, 0xd2]);
            rel(&mut child, 0x1800, &[0x4c, 0x8d, 0x05], 0x2b90);
            rel(&mut child, 0x1800, &[0xff, 0x15], 0x2088);
            child.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]);
        } else {
            child.extend([0x90, 0xeb, 0xfd]);
        }
        image[0xa00..0xa00 + child.len()].copy_from_slice(&child);
        image
    }
    #[test]
    fn debug_control_same_owner_quanta_preserve_pending_branches_and_identical_guest_time() {
        let baseline =
            crate::run_generated_image(&quantum_image(false, true), 10000, 30_000_000).unwrap();
        let traced =
            crate::run_generated_image(&quantum_image(true, true), 10000, 30_000_000).unwrap();
        assert_eq!(baseline.error, None, "{baseline:#?}");
        assert_eq!(traced.error, None, "{traced:#?}");
        assert_eq!(traced.guest_entry_return, Some(42));
        assert_eq!(traced.instruction_count, baseline.instruction_count);
        assert_eq!(traced.virtual_tsc, baseline.virtual_tsc);
        let threads = traced.kernel_threads.unwrap();
        assert_eq!(threads.switches, baseline.kernel_threads.unwrap().switches);
        assert!(threads.switches >= 6);
        let report = traced.cpu.debug_control.unwrap();
        let device = &report.processors[&0];
        assert_eq!(device.device.read(), 0);
        assert!(device.pending.is_none());
        assert_eq!(device.device.edges().len(), 32);
        assert_eq!(
            serde_json::to_value(&device.device).unwrap()["recorded_edges"],
            300
        );
        assert!(device.device.edges().all(|edge| edge.to == edge.from + 2));
    }
    #[test]
    fn debug_control_real_owner_changes_remain_explicit_before_context_restore() {
        let result =
            crate::run_generated_image(&quantum_image(true, false), 10000, 30_000_000).unwrap();
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains("scheduler ownership transition")),
            "{result:#?}"
        );
        assert_eq!(result.guest_entry_return, None);
        let report = result.cpu.debug_control.unwrap();
        assert_eq!(report.processors[&0].device.read(), 3);
    }
    fn write(code: &mut Vec<u8>, value: u32) {
        code.push(0xb8);
        code.extend(value.to_le_bytes());
        code.extend([0x31, 0xd2, 0x0f, 0x30]);
    }
    fn readback() -> Vec<u8> {
        // Save original EDX:EAX, write3/read, restore original, then assert all
        // readback bits in actual guest instructions before returning42.
        vec![
            0xb9, 0xd9, 1, 0, 0, 0x0f, 0x32, 0x41, 0x89, 0xc2, 0x41, 0x89, 0xd3, 0xb8, 3, 0, 0, 0,
            0x31, 0xd2, 0x0f, 0x30, 0x0f, 0x32, 0x41, 0x89, 0xc0, 0x41, 0x89, 0xd1, 0x44, 0x89,
            0xd0, 0x44, 0x89, 0xda, 0x0f, 0x30, 0x41, 0x83, 0xf8, 3, 0x74, 2, 0x0f, 0x0b, 0x45,
            0x85, 0xc9, 0x74, 2, 0x0f, 0x0b, 0xb8, 42, 0, 0, 0, 0xc3,
        ]
    }
    #[test]
    fn debug_control_guest_readback_restore_and_budget_prefixes_are_real() {
        let image = image(&readback());
        let full = crate::run_generated_image(&image, 1000, 30_000_000).unwrap();
        assert_eq!(full.error, None, "{full:#?}");
        assert_eq!(full.guest_entry_return, Some(42));
        let report = full.cpu.debug_control.unwrap();
        assert_eq!(report.processors.len(), 1);
        let cpu = &report.processors[&0];
        assert_eq!((cpu.reads, cpu.writes, cpu.device.read()), (2, 2, 0));
        assert_eq!(cpu.device.edges().len(), 0);
        assert!(full.native_cpu_reads.is_none());
        for budget in [1, 6, 7, full.instruction_count - 1] {
            let partial = crate::run_generated_image(&image, budget, 30_000_000).unwrap();
            assert_eq!(partial.error, None, "{partial:#?}");
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.instruction_count, budget);
            assert_eq!(partial.guest_entry_return, None);
        }
    }
    #[test]
    fn debug_control_guest_taken_conditional_zero_displacement_call_return_are_recorded() {
        let mut code = vec![0xb9, 0xd9, 1, 0, 0];
        write(&mut code, 3);
        code.extend([0x31, 0xc0]);
        let jz = code.len();
        code.extend([0x74, 2, 0x0f, 0x0b]);
        code.extend([0x75, 0, 0x90]); // Not taken, therefore absent from LBR.
        let jump = code.len();
        code.extend([0xeb, 0]); // Taken even though destination is fallthrough.
        let call = code.len();
        code.extend([0xe8, 0, 0, 0, 0]);
        write(&mut code, 0);
        code.extend([0xb8, 42, 0, 0, 0, 0xc3]);
        let leaf = code.len();
        code.extend([0x90, 0xc3]);
        code[call + 1..call + 5].copy_from_slice(&((leaf - call - 5) as i32).to_le_bytes());
        let result = crate::run_generated_image(&image(&code), 1000, 30_000_000).unwrap();
        assert_eq!(result.error, None, "{result:#?}");
        assert_eq!(result.guest_entry_return, Some(42));
        let base = result.image_load.base + 0x1000;
        let report = result.cpu.debug_control.unwrap();
        let edges: Vec<_> = report.processors[&0]
            .device
            .edges()
            .map(|e| (e.from - base, e.to - base))
            .collect();
        assert_eq!(
            edges,
            vec![
                (jz as u64, (jz + 4) as u64),
                (jump as u64, (jump + 2) as u64),
                (call as u64, leaf as u64),
                ((leaf + 1) as u64, (call + 5) as u64)
            ]
        );
        assert_eq!(report.processors[&0].device.read(), 0);
        assert!(report.processors[&0].pending.is_none());
    }
    #[test]
    fn debug_control_unsupported_controls_data_banks_and_native_faults_never_succeed() {
        for (index, value, expected) in [
            (0x1d9u32, 0x80, "other than LBR/BTF"),
            (0x1c9, 0, "format and prediction metadata"),
        ] {
            let mut code = vec![0xb9];
            code.extend(index.to_le_bytes());
            write(&mut code, value);
            code.extend([0xb8, 42, 0, 0, 0, 0xc3]);
            let result = crate::run_generated_image(&image(&code), 1000, 30_000_000).unwrap();
            assert!(
                result
                    .error
                    .as_deref()
                    .is_some_and(|e| e.contains(expected)),
                "{result:#?}"
            );
            assert_eq!(result.guest_entry_return, None);
            assert!(result.cpu.debug_control.is_none());
        }
        let mut code = vec![0xb9, 0xd9, 1, 0, 0];
        write(&mut code, 3);
        code.extend([0x0f, 0x0b]);
        let result = crate::run_generated_image(&image(&code), 1000, 30_000_000).unwrap();
        assert!(result.error.is_some());
        assert_eq!(result.guest_entry_return, None);
        let report = result.cpu.debug_control.unwrap();
        assert_eq!(report.processors[&0].device.read(), 3);
        assert_eq!(report.processors[&0].device.edges().len(), 0);
    }
    #[test]
    fn debug_control_cpu_banks_survive_native_context_changes_and_refuse_tf_without_effects() {
        let observed = (|| -> Result<(u64, u64, String, usize)> {
            let mut engine = crate::new_engine(Architecture::X64)?;
            engine.get_data_mut().apis.kernel_mode = true;
            uc(engine.reg_write(RegisterX86::RAX, 3))?;
            uc(engine.reg_write(RegisterX86::RDX, 0))?;
            msr(&mut engine, 0x1000, 2, 0x1d9, true)?;
            engine.get_data_mut().cpu.processor = 1;
            msr(&mut engine, 0x1002, 2, 0x1d9, false)?;
            let other = uc(engine.reg_read(RegisterX86::RAX))?;
            engine.get_data_mut().cpu.processor = 0;
            msr(&mut engine, 0x1004, 2, 0x1d9, false)?;
            let original = uc(engine.reg_read(RegisterX86::RAX))?;
            engine.get_data_mut().cpu.processor = 2;
            uc(engine.reg_write(RegisterX86::EFLAGS, 0x102))?;
            let error = msr(&mut engine, 0x1006, 2, 0x1d9, true)
                .err()
                .context("TF/BTF was silently accepted")?
                .to_string();
            Ok((
                other,
                original,
                error,
                engine.get_data().cpu.debug_control.processors.len(),
            ))
        })()
        .unwrap();
        assert_eq!((observed.0, observed.1), (0, 3));
        assert!(observed.2.contains("branch-step"));
        assert_eq!(observed.3, 2);
    }
    #[test]
    fn debug_control_decoder_recognizes_near_branches_and_refuses_far_exception_edges() {
        for bytes in [&[0x67, 0xe3, 0][..], &[0x0f, 0x85, 0, 0, 0, 0], &[0x75, 0]] {
            assert_eq!(branch(bytes).unwrap(), Some(false));
        }
        for bytes in [
            &[0x48, 0xff, 0x10][..],
            &[0xc3],
            &[0xeb, 0],
            &[0xe8, 0, 0, 0, 0],
        ] {
            assert_eq!(branch(bytes).unwrap(), Some(true));
        }
        assert_eq!(branch(&[0xff, 0xc0]).unwrap(), None);
        assert!(branch(&[0xcb]).is_err());
        assert!(branch(&[0x0f, 0x05]).is_err());
    }
    #[test]
    fn debug_control_branch_attempts_and_active_api_boundaries_do_not_invent_effects() {
        let mut code = vec![0xb9, 0xd9, 1, 0, 0];
        write(&mut code, 3);
        code.extend([0x31, 0xc0, 0xff, 0xe0]);
        let failed = crate::run_generated_image(&image(&code), 1000, 30_000_000).unwrap();
        assert!(failed.error.is_some());
        assert_eq!(failed.guest_entry_return, None);
        let report = failed.cpu.debug_control.unwrap();
        assert_eq!(report.processors[&0].device.edges().len(), 0);
        assert!(report.processors[&0].pending.is_some());
        let mut code = vec![0xb9, 0xd9, 1, 0, 0];
        write(&mut code, 3);
        code.extend([0x48, 0x83, 0xec, 0x28]);
        let call = code.len();
        code.extend([0xff, 0x15]);
        let displacement = 0x2160i32 - (0x1000 + code.len() + 4) as i32;
        code.extend(displacement.to_le_bytes());
        code.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]);
        let mut bytes = image(&code);
        let put = |data: &mut [u8], at: usize, value: u32| {
            data[at..at + 4].copy_from_slice(&value.to_le_bytes())
        };
        put(&mut bytes, 0x98 + 112 + 8, 0x2100);
        put(&mut bytes, 0x98 + 112 + 12, 40);
        bytes[0x500..0x600].fill(0);
        for (i, value) in [0x2140, 0, 0, 0x2128, 0x2160].into_iter().enumerate() {
            put(&mut bytes, 0x500 + i * 4, value);
        }
        bytes[0x528..0x535].copy_from_slice(b"ntoskrnl.exe\0");
        for at in [0x540, 0x560] {
            bytes[at..at + 8].copy_from_slice(&0x2180u64.to_le_bytes());
        }
        let name = b"KeGetCurrentIrql\0";
        bytes[0x582..0x582 + name.len()].copy_from_slice(name);
        let failed = crate::run_generated_image(&bytes, 1000, 30_000_000).unwrap();
        assert!(
            failed
                .error
                .as_deref()
                .is_some_and(|e| e.contains("active API boundary")),
            "{failed:#?}"
        );
        assert_eq!(failed.guest_entry_return, None);
        assert_eq!(failed.api_calls, 0);
        let report = failed.cpu.debug_control.unwrap();
        let edges: Vec<_> = report.processors[&0].device.edges().collect();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].from, failed.image_load.base + 0x1000 + call as u64);
        assert!(report.processors[&0].pending.is_none());
    }
    #[test]
    fn debug_control_foreign_mode_and_unqualified_cpu_profiles_are_not_published() {
        let errors = (|| -> Result<Vec<String>> {
            let mut engine = crate::new_engine(Architecture::X64)?;
            let mut errors = Vec::new();
            errors.push(
                msr(&mut engine, 0x1000, 2, 0x1d9, false)
                    .err()
                    .context("User DEBUGCTL accepted")?
                    .to_string(),
            );
            engine.get_data_mut().apis.kernel_mode = true;
            engine.get_data_mut().cpu.profile.signature = 0;
            errors.push(
                msr(&mut engine, 0x1000, 2, 0x1d9, false)
                    .err()
                    .context("Unqualified CPU accepted")?
                    .to_string(),
            );
            ensure!(
                engine.get_data().cpu.debug_control.processors.is_empty(),
                "Refusal published a device"
            );
            Ok(errors)
        })()
        .unwrap();
        assert!(errors[0].contains("CPL0"));
        assert!(errors[1].contains("profile"));
    }
}
