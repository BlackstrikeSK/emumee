use super::*;
use crate::{memory::Permissions, pe::Architecture};
use serde_json::Value;

fn registers(v: &Value) -> Registers {
    let x = |name: &str| v[name].as_u64().unwrap();
    Registers {
        rax: x("rax"),
        rbx: x("rbx"),
        rcx: x("rcx"),
        rdx: x("rdx"),
        rbp: x("rbp"),
        rsi: x("rsi"),
        rdi: x("rdi"),
        rsp: x("rsp"),
        r8: x("r8"),
        r9: x("r9"),
        r10: x("r10"),
        r11: x("r11"),
        r14: x("r14"),
        r15: x("r15"),
    }
}

#[test]
fn native_nonpresent_data_abi_and_ordered_spills_match_complete_oracles() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native_physical_absent.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["kernel_sha256"],
        "4a6af9a3dbbeb440c4a9fbe8a4d6832eae751ac3a85860d860b8313a737a2e3a"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 1024);
    for (index, case) in cases.iter().enumerate() {
        let absent = Absent {
            virtual_address: case["virtual_address"].as_u64().unwrap(),
            first_missing_level: case["first_missing_level"].as_u64().unwrap() as u8,
        };
        let projection = project_absent(
            absent,
            registers(&case["before"]),
            0xad7,
            0xffff_f800_0040_0000,
            case["classification"].as_u64().map(|x| x as u8),
        )
        .unwrap();
        assert_eq!(
            projection.registers,
            registers(&case["after"]),
            "case{index}"
        );
        assert_eq!(
            serde_json::to_value(&projection.spills).unwrap(),
            case["writes"],
            "case{index}"
        );
        assert_eq!(
            serde_json::to_value(projection.pte_addresses).unwrap(),
            case["pte_addresses"]
        );
        assert_eq!(projection.flags & 0x8d5, 0x44);
        assert_eq!(projection.flags & !0x8d5, 0xad7 & !0x8d5);
    }
}

#[test]
fn owned_hierarchy_tracks_actual_mapping_lifetime_and_ignores_permissions_for_presence() {
    assert_eq!(
        absent_in_owned_space(&AddressSpace::new(Architecture::X86), 0x1000),
        Err(Refusal::WrongArchitecture)
    );
    let mut memory = AddressSpace::new(Architecture::X64);
    let query = 0x8040201000;
    let missing = |space: &AddressSpace| {
        absent_in_owned_space(space, query)
            .unwrap()
            .map(|a| a.first_missing_level)
    };
    assert_eq!(missing(&memory), Some(0));
    memory
        .map(0x8000000000, 4096, Permissions::NONE, None, "owned")
        .unwrap();
    assert_eq!(missing(&memory), Some(1));
    memory
        .map(0x8040000000, 4096, Permissions::READ, None, "owned")
        .unwrap();
    assert_eq!(missing(&memory), Some(2));
    memory
        .map(0x8040200000, 4096, Permissions::WRITE, None, "owned")
        .unwrap();
    assert_eq!(missing(&memory), Some(3));
    memory
        .map(query, 4096, Permissions::NONE, None, "owned")
        .unwrap();
    assert_eq!(missing(&memory), None);
    memory.unmap(query, 4096).unwrap();
    assert_eq!(missing(&memory), Some(3));
    memory.unmap(0x8040200000, 4096).unwrap();
    assert_eq!(missing(&memory), Some(2));
    let raw = 0x800000000000;
    let raw_absent = absent_in_owned_space(&memory, raw).unwrap().unwrap();
    assert_eq!(raw_absent.virtual_address, raw);
    assert_eq!(raw_absent.first_missing_level, 0);
    assert_eq!(paging_alias(raw), 0xffff_8000_0000_0000);
    assert_eq!(paging_alias(0x1234_8040_2010_0000), 0xffff_8040_2010_0000);
    // AddressSpace's exclusive end cannot represent a mapping ending at2^64.
    assert!(
        memory
            .map(
                0xffff_ffff_ffff_f000,
                4096,
                Permissions::READ,
                None,
                "final"
            )
            .is_err()
    );
    memory
        .map(
            0xffff_ffff_ffff_e000,
            4096,
            Permissions::READ,
            None,
            "near-final",
        )
        .unwrap();
    assert_eq!(
        absent_in_owned_space(&memory, u64::MAX)
            .unwrap()
            .unwrap()
            .first_missing_level,
        3
    );
}

#[test]
fn missing_native_context_and_aliases_remain_refusals_without_effects() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native_physical_absent.json"
    ))
    .unwrap();
    let mut regs = registers(&fixture["cases"][0]["before"]);
    let mut absent = Absent {
        virtual_address: 0xffff_f801_0018_f098,
        first_missing_level: 3,
    };
    regs.rcx = absent.virtual_address;
    assert_eq!(
        project_absent(absent, regs, 2, 0xffff_f800_0040_0000, None),
        Err(Refusal::NeedsKernelClassification)
    );
    assert_eq!(
        project_absent(absent, regs, 2, 0xffff_f800_0040_0000, Some(11)),
        Err(Refusal::NeedsDriverAddressLog)
    );
    let class_offset = 0xe3_8aa8 + ((absent.virtual_address >> 39) & 511) - 256;
    assert_eq!(
        project_absent(absent, regs, 2, regs.rsp - 8 - class_offset, Some(0)),
        Err(Refusal::KernelGeometry)
    );
    assert_eq!(
        project_absent(absent, regs, 2, u64::MAX, Some(0)),
        Err(Refusal::KernelGeometry)
    );
    absent.virtual_address = 0xffff_f6fb_7dbe_d000;
    regs.rcx = absent.virtual_address;
    assert_eq!(
        project_absent(absent, regs, 2, 0xffff_f800_0040_0000, Some(0)),
        Err(Refusal::AliasedPteAddresses)
    );
    absent.virtual_address = 0x8040201000;
    regs.rcx = absent.virtual_address;
    absent.first_missing_level = 4;
    assert_eq!(
        project_absent(absent, regs, 2, 0, None),
        Err(Refusal::InvalidLevel)
    );
    absent.first_missing_level = 0;
    regs.rcx = 0;
    assert_eq!(
        project_absent(absent, regs, 2, 0, None),
        Err(Refusal::ArgumentMismatch)
    );
    regs.rcx = absent.virtual_address;
    regs.rsp = 0x70;
    assert_eq!(
        project_absent(absent, regs, 2, 0, None),
        Err(Refusal::StackGeometry)
    );
}
