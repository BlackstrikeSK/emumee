use super::*;
use crate::{
    kernel_paging::Authority,
    memory::{AddressSpace, Permissions},
    pe::Architecture,
};
use serde_json::Value;

fn registers(value: &Value) -> Registers {
    let words: Vec<u64> = value
        .as_array()
        .unwrap()
        .iter()
        .map(|word| word.as_u64().unwrap())
        .collect();
    Registers {
        rax: words[0],
        rbx: words[1],
        rcx: words[2],
        rdx: words[3],
        rbp: words[4],
        rsi: words[5],
        rdi: words[6],
        rsp: words[7],
        r8: words[8],
        r9: words[9],
        r10: words[10],
        r11: words[11],
        r14: words[12],
        r15: words[13],
    }
}

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/native_physical_owned.json"
    ))
    .unwrap()
}

#[test]
fn actual_entry_abi_matches_independent_native_instruction_oracle() {
    let fixture = fixture();
    assert_eq!(
        fixture["kernel_sha256"],
        "4a6af9a3dbbeb440c4a9fbe8a4d6832eae751ac3a85860d860b8313a737a2e3a"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 160);
    for (index, case) in cases.iter().enumerate() {
        let entries = std::array::from_fn(|level| case["entries"][level].as_u64());
        let walk = Walk {
            virtual_address: case["address"].as_u64().unwrap(),
            entries,
        };
        let projection = project(&walk, registers(&case["before"]), 0xad7).unwrap();
        assert_eq!(
            projection.registers,
            registers(&case["after"]),
            "case{index}"
        );
        assert_eq!(
            serde_json::to_value(projection.pte_addresses).unwrap(),
            case["ptes"],
            "case{index}"
        );
        assert_eq!(
            projection.flags & 0x8d5,
            case["flags"].as_u64().unwrap(),
            "case{index}"
        );
        assert_eq!(projection.flags & !0x8d5, 0xad7 & !0x8d5);
        let expected: Vec<Spill> = case["spills"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| Spill {
                address: row[0].as_u64().unwrap(),
                bytes: row[2].as_u64().unwrap().to_le_bytes()[..row[1].as_u64().unwrap() as usize]
                    .to_vec(),
            })
            .collect();
        assert_eq!(projection.spills, expected, "case{index}");
    }
}

#[test]
fn actual_owned_walk_words_match_table_bytes_and_translation() {
    let mut memory = AddressSpace::new(Architecture::X64);
    memory
        .map(0x140000000, 4096, Permissions::RX, Some(4), "owned test")
        .unwrap();
    let mut authority = Authority::new(&memory).unwrap();
    for address in [
        0x140000321,
        0xf6fb7dbed321,
        0x1234f6fb7dbed321,
        0x8040201000,
    ] {
        let walk = authority.walk(&memory, address).unwrap();
        let mut frame = authority.cr3() >> 12;
        for (level, entry) in walk.entries.into_iter().enumerate() {
            let Some(word) = entry else { break };
            let bytes = authority.table_bytes(&memory, frame).unwrap();
            let offset = ((address >> (39 - level * 9)) & 511) as usize * 8;
            assert_eq!(
                word,
                u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
            );
            if word & 1 == 0 {
                break;
            }
            frame = (word & 0x000f_ffff_ffff_f000) >> 12;
        }
        let physical = authority.translate(&memory, address).unwrap();
        assert_eq!(
            physical,
            walk.entries[3]
                .filter(|word| word & 1 != 0)
                .map(|word| (word & 0x000f_ffff_ffff_f000) | (address & 4095))
        );
    }
}

#[test]
fn unsupported_native_paths_are_refused_before_effects() {
    let fixture = fixture();
    let case = &fixture["cases"][4];
    let mut before = registers(&case["before"]);
    let mut walk = Walk {
        virtual_address: before.rcx,
        entries: [Some(0x100063); 4],
    };
    walk.entries[1] = Some(0x1000e3);
    assert_eq!(project(&walk, before, 2), Err(Refusal::NeedsLargePage));
    walk.entries[1] = Some(0x100063);
    before.rcx = 0xffff800140000000;
    walk.virtual_address = before.rcx;
    assert_eq!(
        project(&walk, before, 2),
        Err(Refusal::NeedsKernelClassification)
    );
    before.rcx = 0xf6fb7dbed000;
    walk.virtual_address = before.rcx;
    walk.entries[1] = Some(0x200063);
    assert_eq!(project(&walk, before, 2), Err(Refusal::AliasedPteAddresses));
    walk.entries = [Some(0x100001); 4];
    before.rcx = 0x140000000;
    walk.virtual_address = before.rcx;
    assert_eq!(project(&walk, before, 2), Err(Refusal::NeedsEntryRepair));
    before.rsp = PML4_START + 0x78;
    assert_eq!(project(&walk, before, 2), Err(Refusal::StackGeometry));
}
