//! Owned guest programs only; no reference PE instructions are executed.
use super::*;
const CODE: u64 = 0x140000000;
const DATA: u64 = 0x280400000;
const ROOT_VIEW: u64 = 0xffff_f6fb_7dbe_d000;
fn map(e: &mut Unicorn<Trace>, at: u64, permissions: P) {
    e.mem_map(at, PAGE, Prot(u32::from(permissions.0) as _))
        .unwrap();
    e.get_data_mut()
        .apis
        .memory
        .map(at, PAGE, permissions, Some(4), "owned paging test")
        .unwrap();
}
fn engine() -> crate::NativeEngine {
    let trace = crate::kernel_capture_tests::prepared(26200, false)
        .into_trace()
        .unwrap();
    let mut e = crate::new_engine_with_trace(trace).unwrap();
    e.get_data_mut()
        .apis
        .target(Architecture::X64, true)
        .unwrap();
    map(&mut e, CODE, P::RX);
    map(&mut e, DATA, P::RW);
    e.get_data_mut().apis.mdls.owned_paging_requested = true;
    crate::kernel_cpu::initialize(&mut e).unwrap();
    e.add_mem_hook(HookType::MEM_READ_UNMAPPED, 1, 0, |e, _, at, size, _| {
        read(e, at, size).unwrap_or(false)
    })
    .unwrap();
    e
}
fn run(e: &mut Unicorn<Trace>, code: &[u8]) -> Result<()> {
    e.mem_write(CODE, code).unwrap();
    e.ctl_remove_cache(CODE, CODE + PAGE).unwrap();
    uc(e.emu_start(CODE, CODE + code.len() as u64, 0, 100))
}
fn load(e: &mut Unicorn<Trace>, at: u64) -> u64 {
    let mut code = vec![0x49, 0xbb]; // mov r11,imm64; mov rax,[r11]; mov rdx,cr3
    code.extend(at.to_le_bytes());
    code.extend([0x49, 0x8b, 0x03, 0x0f, 0x20, 0xda]);
    run(e, &code).unwrap();
    assert!(
        e.get_data().apis.fault.is_none(),
        "{:?}",
        e.get_data().apis.fault
    );
    uc(e.reg_read(RegisterX86::RAX)).unwrap()
}
fn pte(at: u64) -> u64 {
    FIRST + ((at >> 9) & 0x7f_ffff_fff8)
}

#[test]
fn guest_cr3_and_root_view_share_owned_identity_and_real_native_permissions() {
    let mut e = engine();
    let cr3 = e.get_data().apis.mdls.model.physical().unwrap().cr3();
    assert_ne!(cr3, 0);
    let initial = crate::kernel_cpu::report(&e).unwrap().unwrap().initial.cr3;
    assert_eq!(initial, cr3);
    assert_eq!(load(&mut e, ROOT_VIEW + 493 * 8), cr3 | 0x63);
    assert_eq!(uc(e.reg_read(RegisterX86::RDX)).unwrap(), cr3);
    assert_eq!(e.get_data().apis.mdls.paging.backing.len(), 1);
    let r = e
        .mem_regions()
        .unwrap()
        .into_iter()
        .find(|r| r.begin == ROOT_VIEW)
        .unwrap();
    assert_eq!(r.perms, Prot::READ.0 as u32);
    assert!(crate::cpu::write(&mut e, ROOT_VIEW, &[0; 8]).is_err());
    // Host writes bypass permissions; guest stores must still fault natively.
    let mut store = vec![0x49, 0xbb];
    store.extend(ROOT_VIEW.to_le_bytes());
    store.extend([0x49, 0x89, 0x03]);
    assert!(run(&mut e, &store).is_err());
    assert_eq!(
        e.mem_read_as_vec(ROOT_VIEW + 493 * 8, 8).unwrap(),
        (cr3 | 0x63).to_le_bytes()
    );
    assert!(call(&mut e, Call::Physical, &[ROOT_VIEW]).is_err());
    assert!(
        super::super::physical::report(&e)
            .owned_queries
            .events
            .is_empty()
    );
    assert!(!e.get_data().apis.mdls.poisoned);
}

#[test]
fn native_views_refresh_permissions_unmap_retired_tables_and_rebind_new_frames() {
    let mut e = engine();
    let at = pte(DATA);
    let first = load(&mut e, at);
    assert_eq!(first & 0x63, 0x63);
    assert_ne!(first & (1 << 63), 0);
    e.mem_protect(DATA, PAGE, Prot::READ).unwrap();
    e.get_data_mut()
        .apis
        .memory
        .protect(DATA, PAGE, P::READ)
        .unwrap();
    let readonly = load(&mut e, at);
    assert_eq!(first & !2, readonly);
    e.mem_unmap(DATA, PAGE).unwrap();
    e.get_data_mut().apis.memory.unmap(DATA, PAGE).unwrap();
    let view_page = at & !(PAGE - 1);
    let old_pfn = e
        .get_data()
        .apis
        .mdls
        .model
        .physical()
        .unwrap()
        .views()
        .find(|(a, _)| **a == view_page)
        .unwrap()
        .1
        .pfn;
    assert!(!read(&mut e, at, 8).unwrap());
    assert!(
        !e.mem_regions()
            .unwrap()
            .iter()
            .any(|r| r.begin <= view_page && r.end >= view_page)
    );
    assert!(
        !e.get_data()
            .apis
            .mdls
            .paging
            .backing
            .contains_key(&view_page)
    );
    assert!(
        e.get_data()
            .apis
            .mdls
            .model
            .physical()
            .unwrap()
            .frame_kind(old_pfn)
            .is_none()
    );
    map(&mut e, DATA, P::RW);
    let replacement = load(&mut e, at);
    assert_ne!(
        first & 0x000f_ffff_ffff_f000,
        replacement & 0x000f_ffff_ffff_f000
    );
    let new_pfn = e
        .get_data()
        .apis
        .mdls
        .model
        .physical()
        .unwrap()
        .views()
        .find(|(a, _)| **a == view_page)
        .unwrap()
        .1
        .pfn;
    assert_ne!(new_pfn, old_pfn);
    assert!(!e.get_data().apis.mdls.poisoned);
}

#[test]
fn clock_backing_aliases_have_one_frame_and_backend_transport_is_not_a_leaf() {
    let mut e = engine();
    crate::time::initialize(&mut e).unwrap();
    let user = load(&mut e, pte(0x7ffe0000));
    let kernel = load(&mut e, pte(0xffff_f780_0000_0000));
    assert_eq!(user & 0x000f_ffff_ffff_f000, kernel & 0x000f_ffff_ffff_f000);
    assert_eq!(user ^ kernel, 4); // U/S is a mapping attribute, not a new frame.
    let state = &e.get_data().apis;
    let plan = state
        .mdls
        .model
        .prepare_physical_sync(&state.memory)
        .unwrap();
    assert_eq!(plan.state.physical().unwrap().data_frames(), 1); // one shared clock frame
    assert!(
        e.get_data()
            .apis
            .mdls
            .model
            .physical()
            .unwrap()
            .tables()
            .count()
            < 30
    );
}

#[test]
fn partial_map_failure_retains_native_backing_and_poison_cannot_be_cleared_by_read() {
    let mut e = engine();
    e.get_data_mut().apis.mdls.paging.fail_after_map = true;
    let before = e.get_data().apis.mdls.model.clone();
    assert!(
        read(&mut e, ROOT_VIEW, 8)
            .unwrap_err()
            .to_string()
            .contains("Injected")
    );
    assert!(e.get_data().apis.mdls.poisoned);
    assert_eq!(e.get_data().apis.mdls.model, before);
    assert_eq!(e.get_data().apis.mdls.paging.backing.len(), 1);
    assert!(
        e.mem_regions()
            .unwrap()
            .iter()
            .any(|r| r.begin == ROOT_VIEW)
    );
    assert!(super::super::completion_error(&e).is_some());
    assert!(read(&mut e, ROOT_VIEW, 8).is_err());
    assert_eq!(e.get_data().apis.mdls.paging.backing.len(), 1);
}

#[test]
fn context_restores_and_control_writes_cannot_change_owned_root_or_paging_mode() {
    let mut e = engine();
    let good = e.context_init().unwrap();
    let cr3 = e.reg_read(RegisterX86::CR3).unwrap();
    e.reg_write(RegisterX86::CR3, cr3 + PAGE).unwrap();
    assert!(require_context(&e).is_err());
    assert!(crate::kernel_cpu::sync(&mut e, 0).is_err());
    assert!(read(&mut e, ROOT_VIEW, 8).is_err());
    e.context_restore(&good).unwrap();
    require_context(&e).unwrap();
    e.mem_write(CODE, &[0x0f, 0x22, 0xd8]).unwrap(); // mov cr3,rax
    e.reg_write(RegisterX86::RAX, cr3).unwrap();
    control_write(&e, CODE, 3).unwrap();
    e.reg_write(RegisterX86::RAX, cr3 + PAGE).unwrap();
    assert!(control_write(&e, CODE, 3).is_err());
    // Verify the instruction observer stops the actual guest mutation first.
    e.add_code_hook(CODE, CODE + PAGE, |e, pc, size| {
        if let Err(error) = crate::cpu::observe(e, pc, size) {
            e.get_data_mut().cpu.fault = Some(format!("{error:#}"));
            let _ = e.emu_stop();
        }
    })
    .unwrap();
    run(&mut e, &[0x0f, 0x22, 0xd8]).unwrap();
    assert!(e.get_data().cpu.fault.as_ref().unwrap().contains("changes"));
    assert_eq!(e.reg_read(RegisterX86::CR3).unwrap(), cr3);
}

#[test]
fn topology_permissions_owner_and_access_bounds_refuse_before_publication() {
    let mut e = engine();
    let before = e.get_data().apis.mdls.model.clone();
    assert!(read(&mut e, ROOT_VIEW, 0).is_err());
    assert!(read(&mut e, LAST, 8).is_err());
    e.mem_protect(DATA, PAGE, Prot::READ).unwrap();
    assert!(
        read(&mut e, ROOT_VIEW, 8)
            .unwrap_err()
            .to_string()
            .contains("permissions")
    );
    assert_eq!(e.get_data().apis.mdls.model, before);
    assert!(e.get_data().apis.mdls.paging.backing.is_empty());
    e.mem_protect(DATA, PAGE, Prot::READ | Prot::WRITE).unwrap();
    e.mem_map(0x300000000, PAGE, Prot::READ).unwrap();
    e.get_data_mut()
        .apis
        .memory
        .map(0x300000000, PAGE, P::READ, Some(8), "foreign process")
        .unwrap();
    assert!(
        read(&mut e, ROOT_VIEW, 8)
            .unwrap_err()
            .to_string()
            .contains("process")
    );
    assert!(e.get_data().apis.mdls.paging.backing.is_empty());
}

#[test]
fn generated_thread_and_ipi_handoffs_retain_the_owned_paging_domain() {
    use emumee_core::fixtures::{ApiFixture, IpiFixture};
    for fixture in [
        ApiFixture::SystemThread,
        ApiFixture::Ipi(IpiFixture::Basic),
        ApiFixture::Ipi(IpiFixture::ChildCaller),
    ] {
        // These IPI programs assert twelve processors in their guest code.
        // The generic configured capture persona has only six; combining the
        // two triggers the fixture's INT3 before any paging-domain assertion.
        let mut document: serde_json::Value =
            serde_json::from_slice(&emumee_core::fixtures::configured_document(
                emumee_core::fixtures::ConfiguredFixture::Kernel,
            ))
            .unwrap();
        document["windows_build"] = serde_json::json!(26200);
        document["cpu"]["cores"] = serde_json::json!(6);
        let prepared = crate::configured::Prepared::new(
            emumee_core::fullpersona::decode(
                &serde_json::to_vec(&document).unwrap(),
                &emumee_core::fullpersona::ResolveContext::default(),
            )
            .unwrap(),
            crate::configured::Request {
                architecture: Architecture::X64,
                kernel: true,
                initial_processor: 0,
                process: None,
                budget: 100000,
                timeout_us: 30000000,
            },
        )
        .unwrap();
        let result = crate::run_generated_with_fixture_configuration(
            &emumee_core::fixtures::api_probe(Architecture::X64, fixture),
            &[],
            100000,
            30000000,
            crate::GeneratedConfiguration {
                owned_paging_requested: true,
                configured: Some(prepared),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.error.is_none(), "{fixture:?}: {:?}", result.error);
        assert!(result.guest_entry_return.is_some(), "{fixture:?}");
        let cpu = result.kernel_cpu.unwrap();
        assert_ne!(cpu.initial.cr3, 0);
        assert_eq!(cpu.initial.cr3, cpu.current.cr3);
        let mdl = result.kernel_mdls.unwrap();
        assert_eq!(cpu.current.cr3, mdl.model.physical().unwrap().cr3());
        assert!(!mdl.native_effect_failure);
        if matches!(fixture, ApiFixture::Ipi(_)) {
            let ipi = result.kernel_ipi.unwrap();
            assert!(!ipi.rendezvous.broadcasts.is_empty());
            assert!(
                ipi.rendezvous
                    .broadcasts
                    .iter()
                    .flat_map(|b| &b.members)
                    .all(|m| m.phase == emumee_core::ipi::Phase::Returned)
            );
        }
    }
}
