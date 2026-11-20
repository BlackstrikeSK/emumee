//! M6 version control family: one modeled Windows identity read through every
//! structure spelling, the documented condition-mask bit packer, and the real
//! hierarchical `VerifyVersionInfo` comparison with its invalid-argument and
//! old-version answers. The guest decides each value itself.
use super::m6::Probe;
use super::winhttp::Arg::Value as V;
use crate::pe::Architecture;

#[derive(Clone, Copy, Debug)]
pub enum M6VersionFixture {
    /// Every structure spelling publishes the same identity.
    Identity,
    /// `VerSetConditionMask` packs exactly one three-bit slot per call.
    Condition,
    /// The hierarchical comparison, field independence and the old-version answer.
    Verify,
    /// Conditions and structures the predicate must reject.
    BadArguments,
}
/// The one modeled Windows identity. The build is the persona machine's own.
const MAJOR: u32 = 10;
const MINOR: u32 = 0;
const BUILD: u32 = 22_631;
const PLATFORM: u32 = 2;
const SUITE: u32 = 0x100;
const PRODUCT: u32 = 1;
/// VER_ type masks and VER_ condition codes.
const VER_MINORVERSION: u64 = 0x01;
const VER_MAJORVERSION: u64 = 0x02;
const VER_BUILDNUMBER: u64 = 0x04;
const VER_PLATFORMID: u64 = 0x08;
const VER_SUITENAME: u64 = 0x40;
const VER_PRODUCT_TYPE: u64 = 0x80;
const VER_EQUAL: u64 = 1;
const VER_GREATER: u64 = 2;
const VER_GREATER_EQUAL: u64 = 3;
const VER_AND: u64 = 6;
const VER_OR: u64 = 7;

const VERSION_EX: usize = 0;
const VERSION_EX_GENERIC: usize = 1;
const VERIFY: usize = 2;
const LAST_ERROR: usize = 3;
const RTL_VERSION: usize = 4;
const CONDITION: usize = 5;
const RTL_VERIFY: usize = 6;
const NT_NUMBERS: usize = 7;

fn imports(unicode: bool) -> [(&'static str, Vec<String>); 2] {
    let s = if unicode { "W" } else { "A" };
    [
        (
            "kernel32.dll",
            vec![
                format!("GetVersionEx{s}"),
                // The generic spelling has no width tail, so its structure
                // layout is decided by the caller's own size field.
                "GetVersionEx".into(),
                format!("VerifyVersionInfo{s}"),
                "GetLastError".into(),
            ],
        ),
        (
            "ntdll.dll",
            vec![
                "RtlGetVersion".into(),
                "VerSetConditionMask".into(),
                "RtlVerifyVersionInfo".into(),
                "RtlGetNtVersionNumbers".into(),
            ],
        ),
    ]
}
/// Size of OSVERSIONINFOEX and the offset of its service-pack fields.
fn layout(wide_text: bool) -> (u64, u64) {
    if wide_text { (284, 276) } else { (156, 148) }
}
/// Compose a condition mask holding one three-bit slot.
fn mask(slot: u32, condition: u64) -> u64 {
    condition << (slot * 3)
}
/// The slot `VerifyVersionInfo` reads a given type mask's condition from.
fn slot(type_mask: u64) -> u32 {
    match type_mask {
        VER_MINORVERSION => 0,
        VER_MAJORVERSION => 1,
        VER_BUILDNUMBER => 2,
        VER_PLATFORMID => 3,
        VER_SUITENAME => 6,
        VER_PRODUCT_TYPE => 7,
        _ => unreachable!("one type mask per condition slot"),
    }
}

pub fn m6_version_probe(
    architecture: Architecture,
    kind: M6VersionFixture,
    unicode: bool,
) -> Vec<u8> {
    use M6VersionFixture as K;
    let mut p = Probe::new(architecture, unicode, &imports(unicode));
    let x86 = !p.wide;
    let (size, pack) = layout(unicode);
    let info = p.scratch(320);
    let numbers = p.scratch(32);
    // VerSetConditionMask takes a ULONGLONG by value: two x86 stack slots.
    let condition_args = |mask: u64, type_mask: u64, condition: u64| {
        if x86 {
            vec![
                V(mask & 0xffff_ffff),
                V(mask >> 32),
                V(type_mask),
                V(condition),
            ]
        } else {
            vec![V(mask), V(type_mask), V(condition)]
        }
    };
    let verify_args = |structure: u64, type_mask: u64, mask: u64| {
        if x86 {
            vec![
                V(structure),
                V(type_mask),
                V(mask & 0xffff_ffff),
                V(mask >> 32),
            ]
        } else {
            vec![V(structure), V(type_mask), V(mask)]
        }
    };
    /// The numbers a predicate request carries, and where they go.
    struct Requested {
        info: u64,
        size: u64,
        pack: u64,
        major: u32,
        minor: u32,
        build: u32,
        suite: u32,
        product: u32,
    }
    /// Fill the structure the predicate reads with the request's own numbers.
    /// Only the fields the predicate reads are written; the service-pack text
    /// area is never an input to it.
    fn request(p: &mut Probe, asked: &Requested) {
        p.set_dword(asked.info, asked.size as u32);
        p.set_dword(asked.info + 4, asked.major);
        p.set_dword(asked.info + 8, asked.minor);
        p.set_dword(asked.info + 12, asked.build);
        p.set_dword(asked.info + 16, PLATFORM);
        // wServicePackMajor and wServicePackMinor share one word pair, and
        // wSuiteMask and wProductType share the next.
        p.set_dword(asked.info + asked.pack, 0);
        p.set_dword(asked.info + asked.pack + 4, asked.suite | (asked.product << 16));
    }
    match kind {
        K::Identity => {
            // Every spelling writes the same identity into the same layout.
            for (index, structure, basic) in [
                (VERSION_EX, size, pack),
                (VERSION_EX_GENERIC, size, pack),
                // The wide structure is the only one RtlGetVersion accepts.
                (RTL_VERSION, 284, 276),
            ] {
                p.poison(info, 6);
                p.poison(info + basic, 2);
                p.set_dword(info, structure as u32);
                p.call(index, &[V(info)]);
                p.eax(if index == RTL_VERSION { 0 } else { 1 });
                p.dword(info, structure as u32);
                p.dword(info + 4, MAJOR);
                p.dword(info + 8, MINOR);
                p.dword(info + 12, BUILD);
                p.dword(info + 16, PLATFORM);
                // The service-pack text is written as zeroes rather than left
                // as whatever the caller's buffer held.
                p.dword(info + 20, 0);
                p.dword(info + basic, 0);
                p.dword(info + basic + 4, SUITE | (PRODUCT << 16));
            }
            // The basic structure, with no suite or product fields, is also
            // accepted; the generic spelling decides its width from the size.
            let basic_size = if unicode { 276 } else { 148 };
            p.set_dword(info, basic_size);
            p.set_dword(info + u64::from(basic_size), 0x5a5a5a5a);
            p.call(VERSION_EX, &[V(info)]);
            p.eax(1);
            p.dword(info + 12, BUILD);
            // Nothing past the basic structure was written.
            p.dword(info + u64::from(basic_size), 0x5a5a5a5a);
            p.set_dword(info, 148);
            p.call(VERSION_EX_GENERIC, &[V(info)]);
            p.eax(1);
            p.dword(info + 12, BUILD);
            // A size that is neither the basic nor the extended structure is an
            // invalid argument, and the Rtl spelling says so as an NTSTATUS.
            p.set_dword(info, 100);
            p.call(VERSION_EX, &[V(info)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(87);
            p.set_dword(info, 100);
            p.call(RTL_VERSION, &[V(info)]);
            p.eax(0xc000000d);
            // RtlGetNtVersionNumbers reports the build with its high nibble set
            // and skips a null output.
            p.poison(numbers, 4);
            p.call(NT_NUMBERS, &[V(numbers), V(numbers + 4), V(numbers + 8)]);
            p.dword(numbers, MAJOR);
            p.dword(numbers + 4, MINOR);
            p.dword(numbers + 8, BUILD | 0xf000_0000);
            p.intact(numbers + 12, 1);
            p.poison(numbers, 4);
            p.call(NT_NUMBERS, &[V(0), V(0), V(numbers + 8)]);
            p.intact(numbers, 1);
            p.intact(numbers + 4, 1);
            p.dword(numbers + 8, BUILD | 0xf000_0000);
        }
        K::Condition => {
            // One slot per call, at three bits per slot.
            let args = condition_args(0, VER_MAJORVERSION, VER_GREATER_EQUAL);
            p.call(CONDITION, &args);
            p.quad(mask(1, VER_GREATER_EQUAL));
            // The accumulated mask is preserved and the new slot added.
            let args = condition_args(
                mask(1, VER_GREATER_EQUAL),
                VER_MINORVERSION,
                VER_GREATER_EQUAL,
            );
            p.call(CONDITION, &args);
            p.quad(mask(1, VER_GREATER_EQUAL) | mask(0, VER_GREATER_EQUAL));
            // A zero type mask or a zero condition leaves the mask alone.
            let args = condition_args(mask(1, VER_GREATER_EQUAL), 0, VER_GREATER_EQUAL);
            p.call(CONDITION, &args);
            p.quad(mask(1, VER_GREATER_EQUAL));
            let args = condition_args(mask(1, VER_GREATER_EQUAL), VER_MAJORVERSION, 0);
            p.call(CONDITION, &args);
            p.quad(mask(1, VER_GREATER_EQUAL));
            // The condition is masked to three bits, so the high bits of 0x0b
            // cannot reach another slot.
            let args = condition_args(0, VER_MAJORVERSION, 0x0b);
            p.call(CONDITION, &args);
            p.quad(mask(1, VER_GREATER_EQUAL));
            // The highest set type bit selects the one slot written.
            let args = condition_args(0, VER_MAJORVERSION | VER_MINORVERSION, VER_GREATER_EQUAL);
            p.call(CONDITION, &args);
            p.quad(mask(1, VER_GREATER_EQUAL));
            // The product-type slot is the highest one, and the packer reaches
            // the upper half of the mask.
            let args = condition_args(0, VER_PRODUCT_TYPE, VER_EQUAL);
            p.call(CONDITION, &args);
            p.quad(mask(7, VER_EQUAL));
            let args = condition_args(0xffff_ffff_0000_0000, VER_MINORVERSION, VER_EQUAL);
            p.call(CONDITION, &args);
            p.quad(0xffff_ffff_0000_0001);
        }
        K::Verify => {
            // Major and minor compare as one ordered sequence, so an exact
            // match satisfies "greater or equal".
            request(
                &mut p,
                &Requested {
                    info,
                    size,
                    pack,
                    major: MAJOR,
                    minor: MINOR,
                    build: BUILD,
                    suite: SUITE,
                    product: PRODUCT,
                },
            );
            let args = verify_args(
                info,
                VER_MAJORVERSION | VER_MINORVERSION,
                mask(1, VER_GREATER_EQUAL),
            );
            p.call(VERIFY, &args);
            p.eax(1);
            // A newer major version than the modeled one is refused, and the
            // Win32 failure is ERROR_OLD_WIN_VERSION.
            request(
                &mut p,
                &Requested {
                    info,
                    size,
                    pack,
                    major: MAJOR + 1,
                    minor: MINOR,
                    build: BUILD,
                    suite: SUITE,
                    product: PRODUCT,
                },
            );
            let args = verify_args(
                info,
                VER_MAJORVERSION | VER_MINORVERSION,
                mask(1, VER_GREATER_EQUAL),
            );
            p.call(VERIFY, &args);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(1150);
            // The first field that differs decides the sequence: a greater
            // major version satisfies the request even though the requested
            // minor version is higher than the modeled one.
            request(
                &mut p,
                &Requested {
                    info,
                    size,
                    pack,
                    major: MAJOR - 1,
                    minor: 9,
                    build: BUILD,
                    suite: SUITE,
                    product: PRODUCT,
                },
            );
            let args = verify_args(
                info,
                VER_MAJORVERSION | VER_MINORVERSION,
                mask(1, VER_GREATER_EQUAL),
            );
            p.call(VERIFY, &args);
            p.eax(1);
            // An exact-match request over the same sequence fails on the minor
            // version alone.
            let args = verify_args(
                info,
                VER_MAJORVERSION | VER_MINORVERSION,
                mask(1, VER_EQUAL),
            );
            p.call(VERIFY, &args);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(1150);
            // The build number is an independent field.
            request(
                &mut p,
                &Requested {
                    info,
                    size,
                    pack,
                    major: MAJOR,
                    minor: MINOR,
                    build: BUILD - 1,
                    suite: SUITE,
                    product: PRODUCT,
                },
            );
            for (type_mask, condition, expected) in [
                (VER_BUILDNUMBER, VER_GREATER, 1u32),
                (VER_BUILDNUMBER, VER_EQUAL, 0),
                (VER_PLATFORMID, VER_EQUAL, 1),
                (VER_PRODUCT_TYPE, VER_EQUAL, 1),
            ] {
                let args = verify_args(info, type_mask, mask(slot(type_mask), condition));
                p.call(VERIFY, &args);
                p.eax(expected);
            }
            // The suite mask is the only field VER_AND and VER_OR accept.
            request(
                &mut p,
                &Requested {
                    info,
                    size,
                    pack,
                    major: MAJOR,
                    minor: MINOR,
                    build: BUILD,
                    suite: SUITE,
                    product: PRODUCT,
                },
            );
            let args = verify_args(info, VER_SUITENAME, mask(6, VER_AND));
            p.call(VERIFY, &args);
            p.eax(1);
            request(
                &mut p,
                &Requested {
                    info,
                    size,
                    pack,
                    major: MAJOR,
                    minor: MINOR,
                    build: BUILD,
                    suite: 0x300,
                    product: PRODUCT,
                },
            );
            let args = verify_args(info, VER_SUITENAME, mask(6, VER_AND));
            p.call(VERIFY, &args);
            p.eax(0);
            let args = verify_args(info, VER_SUITENAME, mask(6, VER_OR));
            p.call(VERIFY, &args);
            p.eax(1);
            request(
                &mut p,
                &Requested {
                    info,
                    size,
                    pack,
                    major: MAJOR,
                    minor: MINOR,
                    build: BUILD,
                    suite: 0x200,
                    product: PRODUCT,
                },
            );
            let args = verify_args(info, VER_SUITENAME, mask(6, VER_OR));
            p.call(VERIFY, &args);
            p.eax(0);
            // The Rtl spelling answers STATUS_SUCCESS and STATUS_REVISION_MISMATCH
            // over the wide structure.
            request(
                &mut p,
                &Requested {
                    info,
                    size: 284,
                    pack: 276,
                    major: MAJOR,
                    minor: MINOR,
                    build: BUILD,
                    suite: SUITE,
                    product: PRODUCT,
                },
            );
            let args = verify_args(info, VER_BUILDNUMBER, mask(2, VER_EQUAL));
            p.call(RTL_VERIFY, &args);
            p.eax(0);
            request(
                &mut p,
                &Requested {
                    info,
                    size: 284,
                    pack: 276,
                    major: MAJOR,
                    minor: MINOR,
                    build: BUILD + 1,
                    suite: SUITE,
                    product: PRODUCT,
                },
            );
            let args = verify_args(info, VER_BUILDNUMBER, mask(2, VER_EQUAL));
            p.call(RTL_VERIFY, &args);
            p.eax(0xc0000059);
        }
        K::BadArguments => {
            request(
                &mut p,
                &Requested {
                    info,
                    size,
                    pack,
                    major: MAJOR,
                    minor: MINOR,
                    build: BUILD,
                    suite: SUITE,
                    product: PRODUCT,
                },
            );
            // VER_AND and VER_OR are defined only for the suite mask.
            for (type_mask, condition) in [
                (VER_MAJORVERSION, VER_AND),
                (VER_BUILDNUMBER, VER_OR),
                (VER_PRODUCT_TYPE, VER_AND),
                // A zero condition for a selected field names no comparison.
                (VER_BUILDNUMBER, 0),
                // VER_EQUAL is not a suite-mask comparison.
                (VER_SUITENAME, VER_EQUAL),
            ] {
                let requested = if condition == 0 {
                    // The mask must be non-zero overall, so another slot carries
                    // a condition while the selected field's slot stays empty.
                    mask(1, VER_GREATER_EQUAL)
                } else {
                    mask(slot(type_mask), condition)
                };
                let args = verify_args(info, type_mask, requested);
                p.call(VERIFY, &args);
                p.eax(0);
                p.call(LAST_ERROR, &[]);
                p.eax(160);
            }
            // An empty type mask, an empty condition mask and a type bit outside
            // the documented eight are all invalid arguments.
            for (type_mask, requested) in [
                (0, mask(1, VER_GREATER_EQUAL)),
                (VER_MAJORVERSION, 0),
                (0x100, mask(1, VER_GREATER_EQUAL)),
            ] {
                let args = verify_args(info, type_mask, requested);
                p.call(VERIFY, &args);
                p.eax(0);
                p.call(LAST_ERROR, &[]);
                p.eax(160);
            }
            // The predicate is defined over OSVERSIONINFOEX; the shorter
            // structure has no suite, product or service-pack fields to read.
            let basic = if unicode { 276u32 } else { 148 };
            p.set_dword(info, basic);
            let args = verify_args(info, VER_MAJORVERSION, mask(1, VER_GREATER_EQUAL));
            p.call(VERIFY, &args);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(160);
            // The Rtl spelling reports the same refusals as STATUS_INVALID_PARAMETER.
            request(
                &mut p,
                &Requested {
                    info,
                    size: 284,
                    pack: 276,
                    major: MAJOR,
                    minor: MINOR,
                    build: BUILD,
                    suite: SUITE,
                    product: PRODUCT,
                },
            );
            let args = verify_args(info, 0, mask(1, VER_GREATER_EQUAL));
            p.call(RTL_VERIFY, &args);
            p.eax(0xc000000d);
            let args = verify_args(info, VER_MAJORVERSION, mask(1, VER_AND));
            p.call(RTL_VERIFY, &args);
            p.eax(0xc000000d);
            p.set_dword(info, 276);
            let args = verify_args(info, VER_MAJORVERSION, mask(1, VER_GREATER_EQUAL));
            p.call(RTL_VERIFY, &args);
            p.eax(0xc000000d);
        }
    }
    p.finish()
}
