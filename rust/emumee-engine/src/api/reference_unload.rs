//! Two explicit fresh-session fields in exact authenticated NT layouts.
//! Native page backing is READ/NX; byte guards keep its private padding opaque.
use super::*;
use std::cell::{Cell, RefCell};
use unicorn_engine::{UcHookId, unicorn_const::HookType};

const SOURCE: &str = "4b954aae4b18a231b2254c0989b1b6bcc55741a8ef90a350f036d09cd480cc99";
const PDB: &str = "5eea0257091c91a86da4a1633248723eb07f08f6d2718447ed4c0a95706790f5";
const PAGE_RVA: u32 = 0xc13000;
const HOST_SOURCE: &str = "4a6af9a3dbbeb440c4a9fbe8a4d6832eae751ac3a85860d860b8313a737a2e3a";
const HOST_PDB: &str = "f4f5c5d8dbaf7df07538df9a4cb788c8d6840bdc06fb61e5977e6617f20e1c10";
const LIMIT: usize = 64;

pub(crate) enum Authority {
    PinnedNt22631,
    PinnedNt26200,
    #[cfg(test)]
    GeneratedNt22631Layout,
}
#[derive(Clone, Debug, Serialize)]
pub struct Field {
    pub name: &'static str,
    pub address: u64,
    pub rva: u32,
    pub width: u64,
    pub value: u64,
}
#[derive(Clone)]
pub(crate) struct Plan {
    pub page: u64,
    pub fields: Vec<Field>,
    generated: bool,
    profile: &'static str,
    reference_sha256: &'static str,
    pdb_sha256: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct ReadEvidence {
    pub name: &'static str,
    pub address: u64,
    pub size: u64,
    pub pc: u64,
    pub instruction_ordinal: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Denial {
    pub address: u64,
    pub size: u64,
    pub access: &'static str,
}
#[derive(Default)]
pub(crate) struct State {
    plan: Option<Plan>,
    reads: u64,
    observations: Vec<ReadEvidence>,
    observations_omitted: u64,
    denials: RefCell<Vec<Denial>>,
    denials_omitted: Cell<u64>,
    guard_installed: bool,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub profile: &'static str,
    pub reference_sha256: &'static str,
    pub pdb_sha256: &'static str,
    pub generated_fixture: bool,
    pub modeled_image_unloads: u64,
    pub fields: Vec<Field>,
    pub native_read_guard_installed: bool,
    pub native_reads: u64,
    pub observations: Vec<ReadEvidence>,
    pub observations_omitted: u64,
    pub denials: Vec<Denial>,
    pub denials_omitted: u64,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().apis.reference_unload;
    let plan = state.plan.as_ref()?;
    Some(Report {
        profile: plan.profile,
        reference_sha256: plan.reference_sha256,
        pdb_sha256: plan.pdb_sha256,
        generated_fixture: plan.generated,
        modeled_image_unloads: 0,
        fields: plan.fields.clone(),
        native_read_guard_installed: state.guard_installed,
        native_reads: state.reads,
        observations: state.observations.clone(),
        observations_omitted: state.observations_omitted,
        denials: state.denials.borrow().clone(),
        denials_omitted: state.denials_omitted.get(),
        scope: "New guest session with no modeled kernel image-unload operations: NULL lazy history pointer and zero index. DriverUnload alone does not unload an image. Values are explicit guest model state, never copied private reference or host history. Only reads wholly inside one field are admitted, including partial reads; private padding, crossings, writes and execution are refused. Native read refusal stops the run without guest continuation; it does not claim rollback of internal fault-instruction effects.",
    })
}
pub(crate) fn plan(
    engine: &Unicorn<Trace>,
    prepared: &reference_mapping::IntegratedPrepared,
) -> Result<Option<Plan>> {
    let Some(authority) = &prepared.unload_authority else {
        return Ok(None);
    };
    let (generated, page_rva, unloaded_rva, last_rva, profile, source, pdb) = match authority {
        Authority::PinnedNt22631 => {
            ensure!(
                prepared.view.source_sha256 == SOURCE
                    && prepared.view.source_size == 12_076_528
                    && prepared.view.image_size == 0x1047000
                    && engine.get_data().machine.windows_build() == 22631,
                "Guest unload-field layout requires the exact pinned NT22631/PDB profile"
            );
            (false, PAGE_RVA, 0xc13098, 0xc13090,
             "fresh-session-nt22631-unload-fields-v1", SOURCE, PDB)
        }
        Authority::PinnedNt26200 => {
            ensure!(
                prepared.view.source_sha256 == HOST_SOURCE
                    && prepared.view.source_size == 13_131_136
                    && prepared.view.image_size == 0x1450000
                    && engine.get_data().machine.windows_build() == 26200,
                "Guest unload-field layout requires the exact host NT26200/PDB profile"
            );
            (false, 0xef5000, 0xef54b0, 0xef54a8,
             "fresh-session-nt26200-unload-fields-v1", HOST_SOURCE, HOST_PDB)
        }
        #[cfg(test)]
        Authority::GeneratedNt22631Layout =>
            (true, PAGE_RVA, 0xc13098, 0xc13090,
             "fresh-session-nt22631-unload-fields-v1", SOURCE, PDB),
    };
    ensure!(
        engine.get_data().apis.reference_unload.plan.is_none()
            && prepared.view.target_base == reference_mapping::PROVIDER_BASE
            && u64::from(page_rva) + 4096 <= u64::from(prepared.view.image_size)
            && prepared.view.sections.iter().all(|s| {
                let end = u64::from(s.rva) + ((s.bytes.len() as u64 + 4095) & !4095);
                u64::from(page_rva) >= end || u64::from(page_rva) + 4096 <= u64::from(s.rva)
            }),
        "Guest unload-field page overlaps reference code or existing model"
    );
    let base = prepared.view.target_base;
    Ok(Some(Plan {
        page: base + u64::from(page_rva),
        generated,
        profile,
        reference_sha256: source,
        pdb_sha256: pdb,
        fields: vec![
            Field {
                name: "MmUnloadedDrivers",
                address: base + u64::from(unloaded_rva),
                rva: unloaded_rva,
                width: 8,
                value: 0,
            },
            Field {
                name: "MmLastUnloadedDriver",
                address: base + u64::from(last_rva),
                rva: last_rva,
                width: 4,
                value: 0,
            },
        ],
    }))
}
fn overlaps(plan: &Plan, address: u64, size: u64) -> bool {
    size != 0 && address < plan.page + 4096 && address.saturating_add(size) > plan.page
}
fn field(plan: &Plan, address: u64, size: u64) -> Option<&Field> {
    let end = address.checked_add(size)?;
    (size != 0).then_some(())?;
    plan.fields
        .iter()
        .find(|f| address >= f.address && end <= f.address + f.width)
}
fn deny(state: &State, address: u64, size: u64, access: &'static str) {
    let mut rows = state.denials.borrow_mut();
    if rows.len() < LIMIT {
        rows.push(Denial {
            address,
            size,
            access,
        });
    } else {
        state
            .denials_omitted
            .set(state.denials_omitted.get().saturating_add(1));
    }
}
pub(crate) fn require_api_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: P,
) -> Result<()> {
    let state = &engine.get_data().apis.reference_unload;
    let Some(plan) = &state.plan else {
        return Ok(());
    };
    if permissions == P::NONE || !overlaps(plan, address, size) {
        return Ok(());
    }
    if permissions == P::READ && field(plan, address, size).is_some() {
        return Ok(());
    }
    let access = if permissions.contains(P::WRITE) {
        "api_write"
    } else if permissions.contains(P::EXECUTE) {
        "api_execute"
    } else {
        "api_read"
    };
    deny(state, address, size, access);
    bail!("Guest unload-history field policy refuses {access} at 0x{address:x} size{size}")
}
pub(crate) fn install_guard(engine: &mut Unicorn<Trace>, plan: &Plan) -> Result<UcHookId> {
    // Adjacent pages remain NONE. Any native read that can successfully touch
    // this READ page therefore starts here and is covered by its range hook.
    uc(engine.add_mem_hook(HookType::MEM_READ, plan.page, plan.page + 4095,
        |engine, _, address, size, _| {
            let size = size as u64;
            let known = engine.get_data().apis.reference_unload.plan.as_ref()
                .and_then(|plan| field(plan, address, size)).map(|f| f.name);
            if let Some(name) = known {
                let pc = engine.pc_read().unwrap_or(0);
                let ordinal = engine.get_data().instructions;
                let state = &mut engine.get_data_mut().apis.reference_unload;
                state.reads = state.reads.saturating_add(1);
                if state.observations.len() < LIMIT {
                    state.observations.push(ReadEvidence { name, address, size, pc,
                        instruction_ordinal: ordinal });
                } else { state.observations_omitted = state.observations_omitted.saturating_add(1); }
            } else {
                deny(&engine.get_data().apis.reference_unload, address, size, "native_read");
                engine.get_data_mut().apis.fault = Some(format!(
                    "Private reference read outside modeled unload-history fields at 0x{address:x} size{size}"));
                let _ = engine.emu_stop();
            }
            true
        }))
}
pub(crate) fn publish(engine: &mut Unicorn<Trace>, plan: Plan) {
    let state = &mut engine.get_data_mut().apis.reference_unload;
    state.plan = Some(plan);
    state.guard_installed = true;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_api_reads_follow_exact_field_policy_and_normal_public_globals_remain_readable() {
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        engine
            .get_data_mut()
            .apis
            .target(Architecture::X64, true)
            .unwrap();
        kernel_objects::initialize(&mut engine).unwrap();
        let prepared = crate::kernel_reference_unload_tests::reference();
        initialize_providers_with_reference(&mut engine, &prepared).unwrap();
        let base = reference_mapping::PROVIDER_BASE;
        for (rva, size) in [(0xc13098, 8), (0xc1309f, 1), (0xc13090, 4)] {
            assert_eq!(
                read(&engine, base + rva, size).unwrap(),
                vec![0; size as usize]
            );
        }
        for (rva, size) in [(0xc13094, 1), (0xc13097, 2), (0xc1309f, 2), (0xc13090, 8)] {
            assert!(read(&engine, base + rva, size).is_err());
        }
        let frame = Frame(&engine);
        assert_eq!(frame.memory(base + 0xc13098, 8).unwrap(), vec![0; 8]);
        assert!(frame.memory(base + 0xc13094, 1).is_err());
        assert!(frame.memory(base + 0xc13090, 8).is_err());
        assert!(require_api_access(&engine, base + 0xc13098, 8, P::WRITE).is_err());
        assert!(require_api_access(&engine, base + 0xc13098, 8, P::EXECUTE).is_err());
        assert!(crate::cpu::write(&mut engine, base + 0xc13098, &[1]).is_err());
        let emumee_core::modules::Resolution::Found { address, .. } = engine
            .get_data()
            .apis
            .modules
            .resolve(
                "ntoskrnl.exe",
                &ImportName::Name("KeNumberProcessors".into()),
            )
            .unwrap()
        else {
            panic!("public configured global missing");
        };
        assert_eq!(read(&engine, address, 1).unwrap().len(), 1);
        assert_eq!(report(&engine).unwrap().native_reads, 0); // Host checks are not guest consumption.
    }
    #[test]
    fn production_layout_authority_refuses_a_generated_reference_identity_before_publication() {
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        engine
            .get_data_mut()
            .apis
            .target(Architecture::X64, true)
            .unwrap();
        let mut prepared = crate::kernel_reference_unload_tests::reference();
        prepared.unload_authority = Some(Authority::PinnedNt22631);
        assert!(plan(&engine, &prepared).is_err());
        assert!(report(&engine).is_none());
    }
}
