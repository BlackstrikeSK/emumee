//! Owned, bounded x64 kernel loader-list projection from the mapped module catalog.
//! The field offsets are from the exact authenticated NT reference PDB. This
//! snapshot does not claim a general kernel loader or all-build private ABI.
use super::*;
use anyhow::{bail, ensure};
use emumee_core::{kernel_layout::KernelLayout, memory::Permissions as P, modules::ModuleOrigin};
use std::cell::{Cell, RefCell};

const PAGE: u64 = 4096;
const NODE_SIZE: usize = 0xa0;
const STRING_OFFSET: usize = 0x100;
pub(crate) const MAX_FULL_NAME_UNITS: usize = (PAGE as usize - STRING_OFFSET - 2) / 2;
const MAX_NODES: usize = 256;
const DENIAL_LIMIT: usize = 64;
const REFERENCE_SHA256: &str = "4b954aae4b18a231b2254c0989b1b6bcc55741a8ef90a350f036d09cd480cc99";
const PDB_SHA256: &str = "5eea0257091c91a86da4a1633248723eb07f08f6d2718447ed4c0a95706790f5";
const HOST_REFERENCE_SHA256: &str = "4a6af9a3dbbeb440c4a9fbe8a4d6832eae751ac3a85860d860b8313a737a2e3a";
const HOST_PDB_SHA256: &str = "f4f5c5d8dbaf7df07538df9a4cb788c8d6840bdc06fb61e5977e6617f20e1c10";

#[derive(Clone, Copy)]
pub(crate) enum Authority {
    GeneratedX64,
    PinnedReferenceX64,
    PinnedHost26200X64,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeEvidence {
    pub name: String,
    pub address: u64,
    pub image_base: u64,
    pub image_size: u64,
    pub entry_point: u64,
    pub guest_path: String,
    pub accepted_image_sha256: String,
    pub origin: ModuleOrigin,
    pub load_order: u16,
    pub full_name_bytes: u16,
    pub base_name_bytes: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct Denial {
    pub address: u64,
    pub size: u64,
    pub access: &'static str,
}

#[derive(Clone)]
struct Plan {
    base: u64,
    size: u64,
    head: u64,
    primary: u64,
    nodes: Vec<NodeEvidence>,
    readable: Vec<(u64, u64)>,
    profile: &'static str,
    reference_sha256: &'static str,
    pdb_sha256: &'static str,
}

#[derive(Default)]
pub(crate) struct State {
    plan: Option<Plan>,
    native_read_guard_installed: bool,
    native_write_guard_installed: bool,
    native_reads: Cell<u64>,
    denials: RefCell<Vec<Denial>>,
    denials_omitted: Cell<u64>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub profile: &'static str,
    pub reference_sha256: &'static str,
    pub pdb_sha256: &'static str,
    pub generated_fixture: bool,
    pub arena_base: u64,
    pub arena_size: u64,
    pub list_head: u64,
    pub driver_section: u64,
    pub nodes: Vec<NodeEvidence>,
    pub native_read_guard_installed: bool,
    pub native_write_guard_installed: bool,
    pub native_reads: u64,
    pub denials: Vec<Denial>,
    pub denials_omitted: u64,
    pub scope: &'static str,
}

pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().kernel_loader;
    let plan = state.plan.as_ref()?;
    Some(Report {
        profile: plan.profile,
        reference_sha256: plan.reference_sha256,
        pdb_sha256: plan.pdb_sha256,
        generated_fixture: plan.profile == "generated-x64-kldr-v1",
        arena_base: plan.base,
        arena_size: plan.size,
        list_head: plan.head,
        driver_section: plan.primary,
        nodes: plan.nodes.clone(),
        native_read_guard_installed: state.native_read_guard_installed,
        native_write_guard_installed: state.native_write_guard_installed,
        native_reads: state.native_reads.get(),
        denials: state.denials.borrow().clone(),
        denials_omitted: state.denials_omitted.get(),
        scope: "Initial owned x64 KLDR_DATA_TABLE_ENTRY list from actual mapped ModuleCatalog identities and declared guest paths. Private field offsets are pinned to each authenticated NT/PDB profile; the 22631 persona uses a 22621.2506 servicing image, while host 26200 uses a 26100.9711 image. One immutable READ/NX snapshot with no dynamic kernel image-loading lifecycle; adjacent pages are reserved NOACCESS to prevent boundary-crossing native reads. Only list links, base/entry/size, two Unicode descriptors and backing UTF-16 names, and accepted PE checksum are readable. All other fields/padding, writes and execution are refused by page bits and native/host guards. No host module enumeration, private NT bytes, placeholder pointer or guest-decision patch.",
    })
}

fn push_denial(state: &State, address: u64, size: u64, access: &'static str) {
    let mut rows = state.denials.borrow_mut();
    if rows.len() < DENIAL_LIMIT {
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

fn overlaps(plan: &Plan, address: u64, size: u64) -> bool {
    size != 0 && address < plan.base + plan.size && address.saturating_add(size) > plan.base
}

fn readable(plan: &Plan, address: u64, size: u64) -> bool {
    let Some(end) = address.checked_add(size) else {
        return false;
    };
    size != 0
        && plan
            .readable
            .iter()
            .any(|(start, stop)| address >= *start && end <= *stop)
}

pub(crate) fn require_api_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: P,
) -> Result<()> {
    let state = &engine.get_data().kernel_loader;
    let Some(plan) = &state.plan else {
        return Ok(());
    };
    if permissions == P::NONE || !overlaps(plan, address, size) {
        return Ok(());
    }
    if permissions == P::READ && readable(plan, address, size) {
        return Ok(());
    }
    push_denial(state, address, size, "host_api_access");
    bail!("Owned kernel loader metadata refuses unsupported API access")
}

pub(crate) fn require_host_write(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    require_api_access(engine, address, size, P::WRITE)
}

fn pointer(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn unicode(bytes: &mut [u8], offset: usize, length: u16, buffer: u64) {
    bytes[offset..offset + 2].copy_from_slice(&length.to_le_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&(length + 2).to_le_bytes());
    pointer(bytes, offset + 8, buffer);
}

fn build_plan(engine: &Unicorn<Trace>, authority: Authority) -> Result<(Plan, Vec<Vec<u8>>)> {
    ensure!(
        engine.get_data().architecture == Architecture::X64 && engine.get_data().apis.kernel_mode,
        "Owned KLDR projection requires x64 kernel target"
    );
    let catalog = &engine.get_data().apis.modules;
    let primary = catalog
        .primary()
        .ok_or_else(|| anyhow!("Primary module missing from loader catalog"))?;
    let mut modules = catalog.modules().collect::<Vec<_>>();
    ensure!(
        !modules.is_empty() && modules.len() <= MAX_NODES,
        "Owned loader module count out of bounds"
    );
    modules.sort_by_key(|m| {
        (
            match m.name.as_str() {
                "ntoskrnl.exe" => 0,
                "hal.dll" => 1,
                _ => 2,
            },
            m.load_order(),
        )
    });
    let base = KernelLayout::for_architecture(Architecture::X64).loader_entries;
    let size = (modules.len() as u64 + 1) * PAGE;
    let mut nodes = Vec::with_capacity(modules.len());
    let mut pages = Vec::with_capacity(modules.len() + 1);
    let mut readable_ranges = vec![(base, base + 16)];
    ensure!(
        NODE_SIZE <= STRING_OFFSET,
        "KLDR layout overlaps Unicode backing"
    );
    let mut head = vec![0u8; PAGE as usize];
    pointer(&mut head, 0, base + PAGE);
    pointer(&mut head, 8, base + modules.len() as u64 * PAGE);
    pages.push(head);
    for (index, module) in modules.iter().enumerate() {
        let provenance = module
            .provenance()
            .ok_or_else(|| anyhow!("Mapped loader module lacks owned guest path provenance"))?;
        ensure!(
            module.size <= u32::MAX as u64
                && (module.entry_rva() == 0 || (module.entry_rva() as u64) < module.size),
            "Mapped loader module PE geometry exceeds KLDR profile"
        );
        let path = &provenance.guest_path;
        let basename = path
            .rsplit('\\')
            .next()
            .ok_or_else(|| anyhow!("Guest module path lacks basename"))?;
        ensure!(
            basename.eq_ignore_ascii_case(&module.name),
            "Loader name differs from module catalog identity"
        );
        let prefix = &path[..path.len() - basename.len()];
        let prefix_utf16 = prefix.encode_utf16().count() * 2;
        let full_utf16: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        ensure!(
            full_utf16.len() <= MAX_FULL_NAME_UNITS * 2
                && full_utf16.len() <= u16::MAX as usize - 2,
            "Owned loader path exceeds single bounded metadata page"
        );
        let full_len = full_utf16.len() as u16;
        let base_len = (full_utf16.len() - prefix_utf16) as u16;
        let address = base + (index as u64 + 1) * PAGE;
        let mut page = vec![0u8; PAGE as usize];
        let previous = if index == 0 { base } else { address - PAGE };
        let next = if index + 1 == modules.len() {
            base
        } else {
            address + PAGE
        };
        pointer(&mut page, 0, next);
        pointer(&mut page, 8, previous);
        pointer(&mut page, 0x30, module.base);
        let entry = if module.entry_rva() == 0 {
            0
        } else {
            module.base + module.entry_rva() as u64
        };
        pointer(&mut page, 0x38, entry);
        page[0x40..0x44].copy_from_slice(&(module.size as u32).to_le_bytes());
        unicode(&mut page, 0x48, full_len, address + STRING_OFFSET as u64);
        unicode(
            &mut page,
            0x58,
            base_len,
            address + STRING_OFFSET as u64 + prefix_utf16 as u64,
        );
        page[0x78..0x7c].copy_from_slice(&provenance.accepted_headers.checksum.to_le_bytes());
        page[STRING_OFFSET..STRING_OFFSET + full_utf16.len()].copy_from_slice(&full_utf16);
        readable_ranges.extend([
            (address, address + 16),
            (address + 0x30, address + 0x44),
            (address + 0x48, address + 0x68),
            (address + 0x78, address + 0x7c),
            (
                address + STRING_OFFSET as u64,
                address + STRING_OFFSET as u64 + full_utf16.len() as u64 + 2,
            ),
        ]);
        nodes.push(NodeEvidence {
            name: module.name.clone(),
            address,
            image_base: module.base,
            image_size: module.size,
            entry_point: entry,
            guest_path: path.clone(),
            accepted_image_sha256: provenance.accepted_image_sha256.clone(),
            origin: provenance.origin,
            load_order: module.load_order(),
            full_name_bytes: full_len,
            base_name_bytes: base_len,
        });
        pages.push(page);
    }
    let primary_address = nodes
        .iter()
        .find(|node| node.name == primary.name && node.image_base == primary.base)
        .ok_or_else(|| anyhow!("Primary loader node not retained in catalog snapshot"))?
        .address;
    let (profile, reference_sha256, pdb_sha256) = match authority {
        Authority::GeneratedX64 => ("generated-x64-kldr-v1", REFERENCE_SHA256, PDB_SHA256),
        Authority::PinnedReferenceX64 => ("pinned-reference-x64-kldr-v1", REFERENCE_SHA256, PDB_SHA256),
        Authority::PinnedHost26200X64 => ("pinned-host26200-x64-kldr-v1", HOST_REFERENCE_SHA256, HOST_PDB_SHA256),
    };
    Ok((
        Plan {
            base,
            size,
            head: base,
            primary: primary_address,
            nodes,
            readable: readable_ranges,
            profile,
            reference_sha256,
            pdb_sha256,
        },
        pages,
    ))
}

pub(crate) fn initialize(engine: &mut Unicorn<Trace>, authority: Authority) -> Result<u64> {
    ensure!(
        engine.get_data().kernel_loader.plan.is_none(),
        "Kernel loader metadata already published"
    );
    let (plan, pages) = build_plan(engine, authority)?;
    for guard in [plan.base - PAGE, plan.base + plan.size] {
        uc(engine.mem_map(guard, PAGE, Prot::NONE))?;
        engine.get_data_mut().apis.memory.map(
            guard,
            PAGE,
            P::NONE,
            None,
            "owned kernel loader boundary guard",
        )?;
    }
    uc(engine.mem_map(plan.base, plan.size, Prot::READ | Prot::WRITE))?;
    engine.get_data_mut().apis.memory.map(
        plan.base,
        plan.size,
        P::RW,
        Some(4),
        "owned kernel loader metadata",
    )?;
    for (index, page) in pages.iter().enumerate() {
        uc(engine.mem_write(plan.base + index as u64 * PAGE, page))?;
    }
    uc(engine.mem_protect(plan.base, plan.size, Prot::READ))?;
    engine
        .get_data_mut()
        .apis
        .memory
        .protect(plan.base, plan.size, P::READ)?;
    let start = plan.base;
    let last = plan.base + plan.size - 1;
    engine.get_data_mut().kernel_loader.plan = Some(plan.clone());
    uc(engine.add_mem_hook(
        HookType::MEM_READ,
        start - PAGE,
        last + PAGE,
        |engine, _, address, size, _| {
            let state = &engine.get_data().kernel_loader;
            if let Some(plan) = &state.plan {
                if !overlaps(plan, address, size as u64) {
                    return true;
                }
                if readable(plan, address, size as u64) {
                    state
                        .native_reads
                        .set(state.native_reads.get().saturating_add(1));
                } else {
                    push_denial(state, address, size as u64, "native_read");
                    engine.get_data_mut().apis.fault =
                        Some("Private kernel loader metadata read refused".into());
                    let _ = engine.emu_stop();
                }
            }
            true
        },
    ))?;
    engine
        .get_data_mut()
        .kernel_loader
        .native_read_guard_installed = true;
    uc(engine.add_mem_hook(
        HookType::MEM_WRITE,
        start,
        last,
        |engine, _, address, size, _| {
            push_denial(
                &engine.get_data().kernel_loader,
                address,
                size as u64,
                "native_write",
            );
            engine.get_data_mut().apis.fault = Some("Kernel loader metadata write refused".into());
            let _ = engine.emu_stop();
            true
        },
    ))?;
    engine
        .get_data_mut()
        .kernel_loader
        .native_write_guard_installed = true;
    Ok(plan.primary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::{fixtures::counted_driver, pe::PeImage};

    fn driver_with_code(code: &[u8]) -> Vec<u8> {
        let mut bytes = counted_driver(Architecture::X64, 1);
        bytes[0x200..0x200 + code.len()].copy_from_slice(code);
        bytes
    }

    fn u64_at(page: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(page[at..at + 8].try_into().unwrap())
    }

    #[test]
    fn typed_pages_bind_primary_catalog_geometry_names_and_circular_list() {
        let mut engine = new_engine(Architecture::X64).unwrap();
        engine
            .get_data_mut()
            .apis
            .target(Architecture::X64, true)
            .unwrap();
        let catalog = &mut engine.get_data_mut().apis.modules;
        let pe = PeImage::parse(&counted_driver(Architecture::X64, 1), "fixture-driver.sys").unwrap();
        catalog
            .add_with_path(
                "fixture-driver.sys",
                pe.image_base,
                &pe,
                r"C:\Windows\System32\drivers\fixture-driver.sys",
                ModuleOrigin::OwnedGenerated,
            )
            .unwrap();
        catalog.set_primary("fixture-driver.sys").unwrap();
        let nt = PeImage::parse(&counted_driver(Architecture::X64, 1), "ntoskrnl.exe").unwrap();
        catalog
            .add_with_path(
                "ntoskrnl.exe",
                0xfffff80000400000,
                &nt,
                r"C:\Windows\system32\ntoskrnl.exe",
                ModuleOrigin::SyntheticProvider,
            )
            .unwrap();
        let (plan, pages) = build_plan(&engine, Authority::GeneratedX64).unwrap();
        assert_eq!(plan.nodes.len(), 2);
        assert_eq!(plan.nodes[0].name, "ntoskrnl.exe");
        assert_eq!(plan.nodes[1].name, "fixture-driver.sys");
        assert_eq!(plan.primary, plan.nodes[1].address);
        assert_eq!(u64_at(&pages[0], 0), plan.nodes[0].address);
        assert_eq!(u64_at(&pages[0], 8), plan.nodes[1].address);
        assert_eq!(u64_at(&pages[1], 0), plan.nodes[1].address);
        assert_eq!(u64_at(&pages[1], 8), plan.head);
        assert_eq!(u64_at(&pages[2], 0), plan.head);
        assert_eq!(u64_at(&pages[2], 8), plan.nodes[0].address);
        assert_eq!(u64_at(&pages[2], 0x30), pe.image_base);
        assert_eq!(u64_at(&pages[2], 0x38), pe.image_base + pe.entry_rva as u64);
        assert_eq!(
            u32::from_le_bytes(pages[2][0x40..0x44].try_into().unwrap()),
            pe.image_size
        );
        assert_eq!(
            u64_at(&pages[2], 0x48 + 8),
            plan.primary + STRING_OFFSET as u64
        );
        assert_eq!(
            u64_at(&pages[2], 0x58 + 8),
            plan.primary
                + STRING_OFFSET as u64
                + "C:\\Windows\\System32\\drivers\\".encode_utf16().count() as u64 * 2
        );
        let path = r"C:\Windows\System32\drivers\fixture-driver.sys";
        let encoded: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(
            &pages[2][STRING_OFFSET..STRING_OFFSET + encoded.len()],
            encoded
        );
        assert!(pages[2][0x68..0x78].iter().all(|b| *b == 0));
        assert!(readable(&plan, plan.primary + 0x30, 20));
        assert!(!readable(&plan, plan.primary + 0x68, 4));
        assert!(overlaps(&plan, plan.base - 4, 8));
        assert!(!readable(&plan, plan.base - 4, 8));
        assert!(!overlaps(&plan, plan.base - 8, 4));
    }

    #[test]
    fn generated_entry_dereferences_real_driver_section_and_private_read_stops() {
        // mov rax,[rcx+28h]; mov rax,[rax+30h]; ret
        let good = driver_with_code(&[0x48, 0x8b, 0x41, 0x28, 0x48, 0x8b, 0x40, 0x30, 0xc3]);
        let result = run_generated_image(&good, 1000, 30_000_000).unwrap();
        assert_eq!(result.error, None, "{:#?}", result.error);
        assert_eq!(result.guest_entry_return, Some(result.image_load.base));
        let loader = result.kernel_loader.as_ref().unwrap();
        assert!(loader.native_read_guard_installed && loader.native_write_guard_installed);
        assert_eq!(
            loader.driver_section,
            loader
                .nodes
                .iter()
                .find(|m| m.image_base == result.image_load.base)
                .unwrap()
                .address
        );
        assert!(loader.native_reads >= 1);
        assert!(loader.denials.is_empty());

        // +10h is an unsupported exception-table member, even though its backing is zero.
        let bad = driver_with_code(&[0x48, 0x8b, 0x41, 0x28, 0x48, 0x8b, 0x40, 0x10, 0xc3]);
        let denied = run_generated_image(&bad, 1000, 30_000_000).unwrap();
        assert!(
            denied
                .error
                .as_deref()
                .unwrap_or("")
                .contains("Private kernel loader metadata read refused")
        );
        assert_eq!(denied.guest_entry_return, None);
        assert!(
            denied
                .kernel_loader
                .unwrap()
                .denials
                .iter()
                .any(|d| d.access == "native_read")
        );

        // An access beginning outside the arena cannot straddle into the list head.
        let mut straddle_code = vec![0x48, 0xb8]; // mov rax, imm64
        straddle_code.extend_from_slice(
            &KernelLayout::for_architecture(Architecture::X64)
                .loader_entries
                .to_le_bytes(),
        );
        straddle_code.extend_from_slice(&[0x48, 0x8b, 0x40, 0xfc, 0xc3]); // mov rax,[rax-4]; ret
        let straddle =
            run_generated_image(&driver_with_code(&straddle_code), 1000, 30_000_000).unwrap();
        assert!(straddle.error.is_some());
        assert_eq!(straddle.guest_entry_return, None);
    }

    #[test]
    fn host_access_and_unpinned_submitted_path_do_not_bypass_authority() {
        let mut engine = new_engine(Architecture::X64).unwrap();
        engine
            .get_data_mut()
            .apis
            .target(Architecture::X64, true)
            .unwrap();
        let pe = PeImage::parse(
            &counted_driver(Architecture::X64, 1),
            "generated-fixture.sys",
        )
        .unwrap();
        engine
            .get_data_mut()
            .apis
            .modules
            .add_with_path(
                "generated-fixture.sys",
                pe.image_base,
                &pe,
                r"C:\emumee\generated-fixture.sys",
                ModuleOrigin::OwnedGenerated,
            )
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .modules
            .set_primary("generated-fixture.sys")
            .unwrap();
        let primary = initialize(&mut engine, Authority::GeneratedX64).unwrap();
        assert!(require_api_access(&engine, primary + 0x30, 8, P::READ).is_ok());
        assert!(require_api_access(&engine, primary + 0x10, 8, P::READ).is_err());
        assert!(require_host_write(&engine, primary + 0x30, 8).is_err());
        assert!(engine.mem_read_as_vec(primary, 0xa0).is_ok()); // Host parser bypasses hooks; API guard is mandatory.
        let report = report(&engine).unwrap();
        assert_eq!(report.denials.len(), 2);
        assert!(report.driver_section != 0);
        drop(engine);

        let submitted = driver_with_code(&[0x48, 0x8b, 0x41, 0x28, 0xc3]);
        let unpinned = run_submitted_driver(&submitted, "TestDrv", 1000, 30_000_000).unwrap();
        assert_eq!(unpinned.guest_entry_return, Some(0));
        assert!(unpinned.kernel_loader.is_none());
        let x86 = run_fixture(Architecture::X86, 1, 1000).unwrap();
        assert!(x86.kernel_loader.is_none());
    }
}
