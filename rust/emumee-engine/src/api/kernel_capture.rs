//! Bounded native rejection behavior, with owned bootstrap provenance.
//! Positive construction remains a refusal; reference code is never executed.
use super::*;
use emumee_core::kernel_capture::{
    admission::{self, Decision, Facts, Inputs, Rejection},
    boot,
};
pub(super) const ROUTINES: &[&str] = &["KeCapturePersistentThreadState"];

#[derive(Default)]
pub(crate) struct State {
    bootstrap: Option<Bootstrap>,
    events: Vec<Event>,
    omitted: u64,
    native_effect_failure: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Bootstrap {
    pub profile: &'static str,
    pub seed_manifest_sha256: Option<String>,
    pub first_open_status: Option<u32>,
    pub preparation: Option<boot::Progress>,
    pub force_dump_disabled: Option<u8>,
    pub pending: Option<String>,
    pub native_boot_executed: bool,
    pub diagnostic_delivery: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub instruction_ordinal: u64,
    pub output: u64,
    pub context: u64,
    pub supplied_thread: u64,
    pub resolved_thread: Option<u64>,
    pub current_thread_slot_read: bool,
    pub reason: Rejection,
    pub returned: u32,
    pub entry_rsp: u64,
    pub native_stack_spills: u32,
    pub epilogue_flags: u64,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub bootstrap: Option<Bootstrap>,
    pub events: Vec<Event>,
    pub events_omitted: u64,
    pub native_effect_failure: bool,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    if !engine.get_data().apis.kernel_mode {
        return None;
    }
    let s = &engine.get_data().apis.kernel_capture;
    Some(Report {
        bootstrap: s.bootstrap.clone(),
        events: s.events.clone(),
        events_omitted: s.omitted,
        native_effect_failure: s.native_effect_failure,
        scope: "Pinned x64 build26200 owned ordinary-stack profile. Fresh configured registry bootstrap applies only a proved nonoptional first-open-failure ForceDumpDisabled1 projection before guest entry; other facts stay unknown. Diagnostic intents are reported, not emitted ETW events/full Windows boot. No supported runtime policy mutator; unmodeled refresh/configuration remains a refusal. KeCapturePersistentThreadState implements null-output/known-policy rejection0 with native prologue spills and epilogue ADD flags; it does not read/write capture records or validate unused pointers. Unknown policy/positive construction, arbitrary stacks, other builds/architectures, native boot parity and successful capture remain unsupported.",
    })
}
pub(crate) fn initialize_boot(engine: &mut Unicorn<Trace>) -> Result<()> {
    ensure!(
        engine.get_data().instructions == 0,
        "Capture boot policy must precede guest instructions"
    );
    ensure!(
        engine.get_data().apis.kernel_capture.bootstrap.is_none(),
        "Capture boot policy already initialized"
    );
    let trace = engine.get_data();
    let mut evidence = Bootstrap {
        profile: "owned-secure-dump-preparation-26200-v1",
        seed_manifest_sha256: trace.machine.receipt().map(|r| r.seed_manifest_sha256),
        first_open_status: None,
        preparation: None,
        force_dump_disabled: None,
        pending: None,
        native_boot_executed: false,
        diagnostic_delivery: "Preparation diagnostic/free intents are a journal only; ETW delivery and complete Windows boot are outside the supported bootstrap profile.",
    };
    let fresh = trace.apis.registry.native_handle_report();
    if trace.architecture != Architecture::X64
        || trace.machine.windows_build() != 26200
        || !trace.machine.is_configured()
    {
        evidence.pending = Some("Requires configured pinned x64 build26200 bootstrap".into());
    } else if fresh.lifetime_issues != 0 || fresh.live != 0 {
        evidence.pending = Some("Registry is not a fresh pre-entry native-handle context".into());
    } else {
        match boot::observe_open_failure(&trace.apis.registry, boot::Query::GuardedHost) {
            Ok(observation) => {
                let mut observations = BTreeMap::new();
                if let Some(observation) = observation {
                    evidence.first_open_status = Some(observation.status);
                    observations.insert(boot::Query::GuardedHost, observation);
                }
                let projection = boot::evaluate(
                    boot::Inputs {
                        output_present: true,
                        initial_state: 0,
                        initial_provisioning_flag: 0,
                    },
                    &observations,
                )?;
                if let boot::Progress::Complete(out) = &projection {
                    ensure!(
                        out.force_dump_disabled == 1
                            && out.state == 3
                            && out.reads == [boot::Query::GuardedHost]
                            && out.release_intents.is_empty()
                            && out.error_event_intent == Some(2),
                        "Unqualified capture preparation projection"
                    );
                    // This owned field is produced here, not loaded from reference
                    // image bytes. It has no supported mutable publication path.
                    evidence.force_dump_disabled = Some(out.force_dump_disabled);
                } else {
                    evidence.pending = Some(format!("Incomplete boot preparation: {projection:?}"));
                }
                evidence.preparation = Some(projection);
            }
            Err(error) => {
                evidence.pending = Some(format!(
                    "Unsupported native boot registry observation: {error}"
                ))
            }
        }
    }
    engine.get_data_mut().apis.kernel_capture.bootstrap = Some(evidence);
    Ok(())
}
pub(crate) fn completion_error(engine: &Unicorn<Trace>) -> Option<String> {
    engine
        .get_data()
        .apis
        .kernel_capture
        .native_effect_failure
        .then(|| "Capture rejection native effect failed; execution cannot resume".into())
}
fn epilogue_flags(entry_rsp: u64, old: u64) -> u64 {
    let before = entry_rsp.wrapping_sub(0x58);
    let (result, carry) = before.overflowing_add(0x40);
    let overflow = (!(before ^ 0x40) & (before ^ result)) >> 63 != 0;
    (old & !0x8d5)
        | u64::from(carry)
        | u64::from((result as u8).count_ones() % 2 == 0) << 2
        | u64::from((before ^ 0x40 ^ result) & 0x10 != 0) << 4
        | u64::from(result == 0) << 6
        | (result >> 63) << 7
        | u64::from(overflow) << 11
}
pub(super) fn call(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(args.len() == 8, "Capture argument count mismatch");
    ensure!(
        engine.get_data().apis.kernel_mode
            && engine.get_data().architecture == Architecture::X64
            && engine.get_data().machine.windows_build() == 26200
            && uc(engine.reg_read(RegisterX86::CS))? & 3 == 0,
        "Persistent capture requires pinned x64 build26200 CPL0"
    );
    ensure!(
        !engine.get_data().apis.kernel_capture.native_effect_failure,
        "Capture native effect failed; execution cannot resume"
    );
    let mut facts = Facts {
        force_dump_disabled: engine
            .get_data()
            .apis
            .kernel_capture
            .bootstrap
            .as_ref()
            .and_then(|b| b.force_dump_disabled),
        ..Facts::default()
    };
    let mut slot_read = false;
    if args[7] != 0 && args[1] == 0 {
        let pcr = crate::kernel_cpu::current_pcr(engine)?;
        ensure!(
            uc(engine.reg_read(RegisterX86::GS_BASE))? == pcr,
            "Capture current-thread GS base differs from owned processor"
        );
        facts.current_thread = Some(u64::from_le_bytes(
            read(engine, pcr + 0x188, 8)?.try_into().unwrap(),
        ));
        slot_read = true;
    }
    let decision = admission::evaluate(
        Inputs {
            output: args[7],
            thread: args[1],
        },
        &facts,
    );
    let reason = match decision {
        Decision::ReturnZero(reason) => reason,
        Decision::Needs(fact) => bail!("Capture policy fact is not qualified: {fact:?}"),
        Decision::Continue { .. } => {
            bail!("Positive persistent capture construction is not implemented")
        }
    };
    let entry = uc(engine.reg_read(RegisterX86::RSP))?;
    let owner = crate::threads::thread_address(engine);
    let bounds = super::kernel_thread_objects::ordinary_stack_fields(engine, owner)?
        .ok_or_else(|| anyhow::anyhow!("Capture rejection requires an owned ordinary stack"))?;
    let lower = entry
        .checked_sub(0x18)
        .ok_or_else(|| anyhow::anyhow!("Capture native frame underflow"))?;
    let upper = entry
        .checked_add(0x48)
        .ok_or_else(|| anyhow::anyhow!("Capture native frame overflow"))?;
    ensure!(
        lower >= bounds.limit && upper <= bounds.base,
        "Capture native ABI/spill frame exceeds owned ordinary stack"
    );
    let mut spills = Vec::new();
    for (address, register) in [
        (entry + 8, RegisterX86::RBX),
        (entry + 0x10, RegisterX86::RSI),
        (entry + 0x18, RegisterX86::RDI),
        (entry + 0x20, RegisterX86::R13),
        (entry - 8, RegisterX86::RBP),
        (entry - 0x10, RegisterX86::R14),
        (entry - 0x18, RegisterX86::R15),
    ] {
        require(engine, address, 8, P::WRITE)?;
        spills.push((address, uc(engine.reg_read(register))?.to_le_bytes()));
    }
    let flags = epilogue_flags(entry, uc(engine.reg_read(RegisterX86::EFLAGS))?);
    engine
        .get_data_mut()
        .apis
        .kernel_capture
        .native_effect_failure = true;
    for (address, bytes) in &spills {
        crate::cpu::write(engine, *address, bytes)?;
    }
    uc(engine.reg_write(RegisterX86::EFLAGS, flags))?;
    let event = Event {
        instruction_ordinal: engine.get_data().instructions,
        output: args[7],
        context: args[0],
        supplied_thread: args[1],
        resolved_thread: if args[7] == 0 {
            None
        } else {
            Some(if args[1] == 0 {
                facts.current_thread.unwrap()
            } else {
                args[1]
            })
        },
        current_thread_slot_read: slot_read,
        reason,
        returned: 0,
        entry_rsp: entry,
        native_stack_spills: 7,
        epilogue_flags: flags,
    };
    let state = &mut engine.get_data_mut().apis.kernel_capture;
    if state.events.len() < 128 {
        state.events.push(event);
    } else {
        state.omitted = state.omitted.saturating_add(1);
    }
    state.native_effect_failure = false;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn epilogue_flags_match_the_actual_owned_add_rsp_instruction() {
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        uc(engine.mem_map(0x100000, 4096, Prot::ALL)).unwrap();
        uc(engine.mem_write(0x100000, &[0x48, 0x83, 0xc4, 0x40])).unwrap();
        for entry in [
            0,
            1,
            0x18,
            0x20,
            0x40,
            0x58,
            0x68,
            0xff,
            0x100,
            0x7fffffffffffffe0,
            0x8000000000000000,
            0xffffa000000ff488,
            u64::MAX,
        ] {
            for flags in [2, 0x202, 0x602, 0xad7] {
                uc(engine.reg_write(RegisterX86::RSP, entry.wrapping_sub(0x58))).unwrap();
                uc(engine.reg_write(RegisterX86::EFLAGS, flags)).unwrap();
                let old = uc(engine.reg_read(RegisterX86::EFLAGS)).unwrap();
                uc(engine.emu_start(0x100000, 0x100004, 0, 1)).unwrap();
                assert_eq!(
                    uc(engine.reg_read(RegisterX86::RSP)).unwrap(),
                    entry.wrapping_sub(0x18)
                );
                assert_eq!(
                    uc(engine.reg_read(RegisterX86::EFLAGS)).unwrap(),
                    epilogue_flags(entry, old),
                    "entry{entry:x} flags{old:x}"
                );
            }
        }
    }
    #[test]
    fn failed_native_spill_latches_fatal_without_fabricated_zero() {
        let prepared = crate::kernel_capture_tests::prepared(26200, false);
        let mut engine = crate::new_engine_with_trace(prepared.into_trace().unwrap()).unwrap();
        engine
            .get_data_mut()
            .apis
            .target(Architecture::X64, true)
            .unwrap();
        crate::api::kernel_objects::initialize(&mut engine).unwrap();
        let layout = emumee_core::kernel_layout::KernelLayout::for_architecture(Architecture::X64);
        for (address, size) in [
            (layout.driver_object, 3 * 4096),
            (
                layout.entry_stack,
                emumee_core::kernel_layout::ENTRY_STACK_SIZE,
            ),
        ] {
            uc(engine.mem_map(address, size, Prot::READ | Prot::WRITE)).unwrap();
            engine
                .get_data_mut()
                .apis
                .memory
                .map(
                    address,
                    size,
                    P::RW,
                    Some(4),
                    "owned capture failure-control storage",
                )
                .unwrap();
        }
        crate::api::kernel_thread_objects::initialize_root(&mut engine).unwrap();
        initialize_boot(&mut engine).unwrap();
        crate::kernel_cpu::initialize(&mut engine).unwrap();
        uc(engine.reg_write(RegisterX86::RSP, layout.entry_stack + 0x800)).unwrap();
        // Deliberately stale logical/native backing, after owned initialization.
        // The model must expose failure rather than reporting a native return0.
        uc(engine.mem_unmap(layout.entry_stack, 4096)).unwrap();
        let error = call(&mut engine, &[0; 8]).unwrap_err();
        assert!(error.to_string().contains("WRITE_UNMAPPED"), "{error}");
        assert!(completion_error(&engine).is_some());
        assert!(report(&engine).unwrap().events.is_empty());
        assert!(
            call(&mut engine, &[0; 8])
                .unwrap_err()
                .to_string()
                .contains("execution cannot resume")
        );
    }
}
