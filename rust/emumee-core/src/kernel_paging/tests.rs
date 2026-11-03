use super::*;
use crate::{
    mdl::{MapRequest, Mdls},
    pool::{Allocation, Pool},
};

fn memory() -> AddressSpace {
    AddressSpace::new(Architecture::X64)
}
fn map(m: &mut AddressSpace, base: u64, pages: u64, p: Permissions) {
    m.map(base, pages * PAGE, p, Some(4), "owned test data")
        .unwrap();
}
fn word(bytes: &[u8], slot: u16) -> u64 {
    u64::from_le_bytes(
        bytes[slot as usize * 8..slot as usize * 8 + 8]
            .try_into()
            .unwrap(),
    )
}
fn root_view() -> u64 {
    canonical_page([SELF_INDEX; 4])
}
/// Independent architectural4-entry walk over physical table bytes. It does
/// not call translate or virtual_key; malformed links fail by frame type.
fn walk(a: &mut Authority, m: &AddressSpace, address: u64) -> Option<u64> {
    let mut frame = a.root_pfn;
    for depth in 0..4 {
        let bytes = a.table_bytes(m, frame).unwrap();
        let e = word(&bytes, slot(address, depth));
        if e & 1 == 0 {
            return None;
        }
        assert_eq!(e & 0x80, 0, "large pages are outside this ordinary profile");
        frame = (e >> 12) & ((1 << 40) - 1);
        if depth == 3 {
            return Some(frame * PAGE + (address & 4095));
        }
        assert!(matches!(a.frame_kind(frame), Some(FrameKind::Table { .. })));
    }
    unreachable!()
}

#[test]
fn root_identity_is_backed_by_a_real_self_referential_table_and_shared_namespace() {
    let mut m = memory();
    map(&mut m, 0x140000000, 2, Permissions::RX);
    map(&mut m, 0xfffff80100000000, 3, Permissions::RW);
    let mut a = Authority::new(&m).unwrap();
    assert_ne!(a.cr3(), 0);
    assert_eq!(a.data_frames(), 0);
    let root = a.table_bytes(&m, a.root_pfn).unwrap();
    assert_eq!(root.len(), 4096);
    assert_eq!(word(&root, SELF_INDEX), a.cr3() | 0x63);
    for offset in [0, 0x321, 4095] {
        for raw in [
            root_view() + offset,
            (root_view() & 0xffff_ffff_ffff) + offset,
            0x1234000000000000 | ((root_view() & 0xffff_ffff_ffff) + offset),
        ] {
            assert_eq!(a.translate(&m, raw).unwrap(), Some(a.cr3() + offset));
            assert_eq!(walk(&mut a, &m, raw), Some(a.cr3() + offset));
        }
    }
    for va in [0x140000000, 0x140001321, 0xfffff80100002fff, 0x8040201000] {
        let by_walk = walk(&mut a, &m, va);
        assert_eq!(a.translate(&m, va).unwrap(), by_walk);
    }
    assert_eq!(a.translate(&m, 0x8040201000).unwrap(), None);
    let p = a.translate(&m, 0x140000000).unwrap().unwrap() / PAGE;
    assert_ne!(p, a.root_pfn);
    assert!(matches!(
        a.frame_kind(p),
        Some(FrameKind::Data {
            source: 0x140000000,
            ..
        })
    ));
    assert_eq!(
        a.frames.len(),
        a.frames.keys().copied().collect::<BTreeSet<_>>().len()
    );
}

#[test]
fn protect_preserves_physical_lease_but_unmap_remap_retires_data_and_empty_tables() {
    let mut m = memory();
    let va = 0x140000000;
    map(&mut m, va, 2, Permissions::RW);
    let mut a = Authority::new(&m).unwrap();
    let pfn = a.data_frame(&m, va).unwrap();
    let id = m.region(va).unwrap().mapping_id();
    let old_tables: Vec<_> = a.tables().filter(|t| t.depth != 0).map(|t| t.pfn).collect();
    m.protect(va, PAGE, Permissions::RX).unwrap();
    assert_eq!(m.region(va).unwrap().mapping_id(), id);
    assert_eq!(a.data_frame(&m, va).unwrap(), pfn);
    let bytes = a
        .table_bytes(&m, a.tables[&key(3, prefix(va, 3))].pfn)
        .unwrap();
    let e = word(&bytes, slot(va, 3));
    assert_eq!(e & 2, 0);
    assert_eq!(e >> 63, 0);
    m.unmap(va, 2 * PAGE).unwrap();
    a.sync(&m).unwrap();
    assert_eq!(a.data_frames(), 0);
    assert_eq!(a.frame_kind(pfn), None);
    assert!(old_tables.iter().all(|p| a.frame_kind(*p).is_none()));
    assert_eq!(a.tables.len(), 1);
    assert_eq!(a.translate(&m, va).unwrap(), None);
    map(&mut m, va, 1, Permissions::READ);
    let next = a.data_frame(&m, va).unwrap();
    assert_ne!(next, pfn);
    assert!(next > pfn);
    assert_ne!(m.region(va).unwrap().mapping_id(), id);
    assert!(old_tables.iter().all(|p| a.frame_kind(*p).is_none()));
    let before = m.clone();
    let epoch = m.epoch();
    assert!(m.unmap(va + PAGE, PAGE).is_err());
    assert_eq!(m, before);
    assert_eq!(m.epoch(), epoch);
}

#[test]
fn declared_aliases_share_data_frames_and_detect_cycles_and_backing_replacement() {
    let mut m = memory();
    let user = 0x7ffe0000;
    let kernel = 0xfffff78000000000;
    let backend = 0x000ff78000000000;
    map(&mut m, user, 1, Permissions::READ);
    let mut a = Authority::new(&m).unwrap();
    map(&mut m, kernel, 1, Permissions::READ);
    map(&mut m, backend, 1, Permissions::READ);
    assert!(a.clone().sync(&m).unwrap_err().0.contains("noncanonical"));
    a.register_transport(&m, backend, kernel).unwrap();
    a.register_alias(&m, kernel, user, 1).unwrap();
    let p = a.data_frame(&m, user).unwrap();
    assert_eq!(a.data_frame(&m, kernel).unwrap(), p);
    assert_eq!(a.translate(&m, backend).unwrap(), Some(p * PAGE));
    assert_eq!(a.data_frames(), 1);
    assert!(a.clone().register_alias(&m, user, kernel, 1).is_err());
    m.protect(user, PAGE, Permissions::RW).unwrap();
    assert_eq!(a.data_frame(&m, kernel).unwrap(), p);
    m.unmap(backend, PAGE).unwrap();
    map(&mut m, backend, 1, Permissions::READ);
    assert!(
        a.clone()
            .sync(&m)
            .unwrap_err()
            .0
            .contains("transport lifetime")
    );
    let mut other = memory();
    map(&mut other, 0x100000, 2, Permissions::RW);
    let mut b = Authority::new(&other).unwrap();
    b.register_alias(&other, 0x101000, 0x100000, 1).unwrap();
    let source = b.data_frame(&other, 0x100000).unwrap();
    assert_eq!(b.data_frame(&other, 0x101000).unwrap(), source);
    other.unmap(0x100000, PAGE).unwrap();
    map(&mut other, 0x100000, 1, Permissions::RW);
    assert!(
        b.clone()
            .data_frame(&other, 0x101000)
            .unwrap_err()
            .0
            .contains("alias backing lifetime")
    );
}

#[test]
fn structural_views_have_typed_lifetimes_and_never_become_data_mappings() {
    let mut m = memory();
    map(&mut m, 0x140000000, 1, Permissions::RW);
    let mut a = Authority::new(&m).unwrap();
    let root = a.cr3();
    let tables = a.tables.len();
    let view = root_view();
    m.map(view, PAGE, Permissions::READ, Some(4), VIEW_TAG)
        .unwrap();
    assert!(
        a.clone()
            .sync(&m)
            .unwrap_err()
            .0
            .contains("reserved self-reference")
    );
    a.register_view(&m, view, a.root_pfn).unwrap();
    assert_eq!(a.translate(&m, view).unwrap(), Some(root));
    assert_eq!(a.tables.len(), tables);
    assert!(a.require_write(view + 8, 1).is_err());
    assert!(a.require_mapping_change(view - 8, 16).is_err());
    a.require_write(view, 0).unwrap();
    let before = a.clone();
    assert!(a.register_view(&m, view, a.root_pfn).is_err());
    assert_eq!(a, before);
    m.protect(view, PAGE, Permissions::RW).unwrap();
    assert!(
        a.clone()
            .sync(&m)
            .unwrap_err()
            .0
            .contains("reserved self-reference")
    );
    m.protect(view, PAGE, Permissions::READ).unwrap();
    a.sync(&m).unwrap();
    a.remove_view(view).unwrap();
    m.unmap(view, PAGE).unwrap();
    a.sync(&m).unwrap();
    assert_eq!(a.cr3(), root);
    assert_eq!(a.tables.len(), tables);
}

#[test]
fn structural_view_plans_map_refresh_rebind_and_unmap_without_committing_input_state() {
    use crate::mdl::ViewEffect;
    let mut m = memory();
    let va = 0x140000000;
    map(&mut m, va, 1, Permissions::RW);
    let state = Mdls::new(Architecture::X64)
        .prepare_owned_paging(&m)
        .unwrap()
        .state;
    let view = canonical_page([SELF_INDEX, slot(va, 0), slot(va, 1), slot(va, 2)]);
    let original = state.clone();
    let original_memory = m.clone();
    assert!(state.prepare_physical_view(&m, va).is_err());
    assert_eq!(state, original);
    assert_eq!(m, original_memory);
    let mapped = state.prepare_physical_view(&m, view).unwrap();
    assert_eq!(mapped.effect, ViewEffect::Map);
    assert_eq!(mapped.bytes.len(), 4096);
    let old = mapped.pfn.unwrap();
    let e = word(&mapped.bytes, slot(va, 3));
    let data = (e >> 12) & ((1 << 40) - 1);
    assert_ne!(e & 1, 0);
    assert_eq!(
        mapped
            .state
            .prepare_physical_address(&mapped.memory, va)
            .unwrap()
            .result,
        data * PAGE
    );
    assert!(mapped.state.require_api_write(view, 1).is_err());
    assert_eq!(state, original);
    let same = mapped
        .state
        .prepare_physical_view(&mapped.memory, view)
        .unwrap();
    assert_eq!(same.effect, ViewEffect::Refresh);
    assert_eq!(same.pfn, Some(old));
    let mut empty = same.memory;
    empty.unmap(va, PAGE).unwrap();
    let synced = same.state.prepare_physical_sync(&empty).unwrap();
    let mut reallocated = empty.clone();
    map(&mut reallocated, va, 1, Permissions::RW);
    let rebound = synced
        .state
        .prepare_physical_view(&reallocated, view)
        .unwrap();
    assert_eq!(rebound.effect, ViewEffect::Rebind);
    assert_eq!(rebound.previous_pfn, Some(old));
    assert_ne!(rebound.pfn, Some(old));
    let mut last = rebound.memory;
    last.unmap(va, PAGE).unwrap();
    let gone = rebound.state.prepare_physical_view(&last, view).unwrap();
    assert_eq!(gone.effect, ViewEffect::Unmap);
    assert!(gone.bytes.is_empty());
    assert!(gone.memory.region(view).is_none());
    assert_eq!(gone.pfn, None);
    assert!(
        gone.state
            .prepare_physical_view(&gone.memory, view)
            .is_err()
    );
}

#[test]
fn mdl_pfn_arrays_user_aliases_and_root_share_one_opt_in_physical_authority() {
    let mut m = memory();
    let source = 0xffffb00000000000;
    let pointer = source + 0x8000;
    map(&mut m, source, 3, Permissions::RW);
    map(&mut m, pointer, 1, Permissions::RW);
    let old = Mdls::new(Architecture::X64);
    let legacy = old.prepare_physical_address(&m, source).unwrap();
    assert_eq!(legacy.result, 256 * PAGE);
    assert!(legacy.state.prepare_owned_paging(&m).is_err());
    let plan = old.prepare_owned_paging(&m).unwrap();
    let root = plan.result;
    let state = plan.state;
    assert_ne!(root, 0);
    assert_eq!(state.frame_count(), 0);
    let layout = state
        .allocation_layout(source + 0x123, 0x1800, 0, 0)
        .unwrap()
        .unwrap();
    let initial = layout.initial_bytes();
    let allocated = state.prepare_allocate(&m, pointer, layout).unwrap();
    let built = allocated
        .state
        .prepare_build(&m, pointer, &initial)
        .unwrap();
    let bytes = &built.writes[0].bytes;
    let first = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
    assert_ne!(first * PAGE, root);
    let physical = built
        .state
        .prepare_physical_address(&m, source + 0x123)
        .unwrap();
    assert_eq!(physical.result, first * PAGE + 0x123);
    let mut pool = Pool::default();
    pool.commit_allocation(Allocation {
        base: source,
        requested: 0x3000,
        mapped: 0x3000,
        tag: 1,
        paged: false,
        executable: false,
        zero_initialized: true,
    });
    let mapped = physical
        .state
        .prepare_map(
            &m,
            &pool,
            MapRequest {
                pointer,
                mode: 1,
                cache: 1,
                requested_address: 0,
                bugcheck_on_failure: 0,
                priority: 0,
                process: 4,
                irql: 0,
            },
        )
        .unwrap();
    let alias = mapped.result;
    let translated = mapped
        .state
        .prepare_physical_address(&mapped.memory, alias)
        .unwrap();
    assert_eq!(translated.result, first * PAGE + 0x123);
    let unmapped = translated
        .state
        .prepare_unmap(&mapped.memory, alias, pointer, 4, 0)
        .unwrap();
    assert_eq!(
        unmapped
            .state
            .prepare_physical_address(&unmapped.memory, alias)
            .unwrap()
            .result,
        0
    );
    let mut remaining = unmapped.memory;
    remaining.unmap(source, 3 * PAGE).unwrap();
    let absent = unmapped
        .state
        .prepare_physical_address(&remaining, source)
        .unwrap();
    assert_eq!(absent.result, 0);
    assert_eq!(absent.state.physical().unwrap().frame_kind(first), None);
    map(&mut remaining, source, 3, Permissions::RW);
    let fresh = absent
        .state
        .prepare_physical_address(&remaining, source)
        .unwrap();
    assert_ne!(fresh.result, first * PAGE);
    assert_eq!(fresh.state.physical().unwrap().cr3(), root);
}

#[test]
fn sparse_walks_cover_multiple_prefixes_without_aliasing_tables_data_or_reserved_geometry() {
    let mut m = memory();
    let mut pages = Vec::new();
    for i in 0..32u64 {
        let address = 0x100000000 + (i << 30) + (((i * 17) & 511) << 21) + ((i * 7) & 511) * PAGE;
        map(
            &mut m,
            address,
            1,
            if i % 2 == 0 {
                Permissions::RW
            } else {
                Permissions::RX
            },
        );
        pages.push(address);
    }
    let mut a = Authority::new(&m).unwrap();
    let root = a.cr3();
    for address in pages {
        let physical = walk(&mut a, &m, address + 37);
        assert!(physical.is_some());
        assert_eq!(a.translate(&m, address + 37).unwrap(), physical);
        assert_eq!(a.translate(&m, address + PAGE).unwrap(), None);
    }
    assert_eq!(a.cr3(), root);
    assert_eq!(a.data_frames(), 32);
    assert!(Authority::new(&AddressSpace::new(Architecture::X86)).is_err());
    let mut reserved = memory();
    map(&mut reserved, root_view(), 1, Permissions::READ);
    assert!(
        Authority::new(&reserved)
            .unwrap_err()
            .0
            .contains("reserved self-reference")
    );
}

#[test]
fn inaccessible_reservations_are_not_present_leaves_but_live_shared_backing_keeps_its_identity() {
    let mut m = memory();
    let source = 0x100000;
    let alias = 0x200000;
    map(&mut m, source, 1, Permissions::RW);
    map(&mut m, alias, 1, Permissions::READ);
    let mut a = Authority::new(&m).unwrap();
    a.register_alias(&m, alias, source, 1).unwrap();
    let p = a.data_frame(&m, source).unwrap();
    m.protect(source, PAGE, Permissions::NONE).unwrap();
    assert_eq!(a.translate(&m, source).unwrap(), None);
    assert_eq!(walk(&mut a, &m, source), None);
    assert_eq!(a.translate(&m, alias).unwrap(), Some(p * PAGE));
    assert_eq!(walk(&mut a, &m, alias), Some(p * PAGE));
    assert!(a.data_frame(&m, source).is_err());
    assert!(a.frame_kind(p).is_some());
    m.protect(source, PAGE, Permissions::RX).unwrap();
    assert_eq!(a.translate(&m, source).unwrap(), Some(p * PAGE));
    for permissions in [Permissions::WRITE, Permissions::EXECUTE, Permissions(6)] {
        let mut invalid = memory();
        map(&mut invalid, source, 1, permissions);
        assert!(
            Authority::new(&invalid)
                .unwrap_err()
                .0
                .contains("readable-leaf")
        );
    }
}
