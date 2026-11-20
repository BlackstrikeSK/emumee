//! M6 file-handle control family: size, end-of-file, pointer movement,
//! per-path times, by-handle information and the legacy file API, each decided
//! by the guest, plus the access boundaries that must refuse.
use super::m6::{POISON, Probe};
use super::winhttp::Arg::{Memory as M, Value as V};
use crate::pe::Architecture;

#[derive(Clone, Copy, Debug)]
pub enum M6FileFixture {
    /// Size reporting, pointer movement and moving the end of the file.
    Size,
    /// Per-path creation, access and write times a guest sets and reads back.
    Times,
    /// BY_HANDLE_FILE_INFORMATION in its exact layout, including the index.
    Information,
    /// The legacy `_lopen`/`_llseek`/`_lclose` spellings and their results.
    Legacy,
    /// A read-only handle cannot stamp, and an append-only handle cannot shorten.
    Denied,
}
/// A base for the timestamps these controls set themselves. The seeded
/// filesystem time comes from the run's own clock, which a contained replay
/// cannot predict, so no control asserts it: every time a control checks is a
/// time the guest wrote.
const STAMP: u64 = 134_377_488_000_000_000;
/// The 32-bit volume serial number derived from the persona volume GUID.
const SERIAL: u32 = 0x6f2a_9e4d;

/// The documented per-path file index: FNV-1a over the canonical path with its
/// low bit set, recomputed here so the control decides the value rather than
/// reading it back from the model that produced it.
fn file_index(path: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in path.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash | 1
}

const CREATE: usize = 0;
const WRITE: usize = 1;
const READ: usize = 2;
const SIZE: usize = 3;
const SEEK: usize = 4;
const END_OF_FILE: usize = 5;
const GET_TIME: usize = 6;
const SET_TIME: usize = 7;
const INFORMATION: usize = 8;
const FLUSH: usize = 9;
const CLOSE: usize = 10;
const ATTRIBUTES: usize = 11;
const LOPEN: usize = 12;
const LCLOSE: usize = 13;
const LSEEK: usize = 14;
const LAST_ERROR: usize = 15;

/// GENERIC_READ|GENERIC_WRITE, GENERIC_READ and FILE_APPEND_DATA.
const RDWR: u64 = 0xc000_0000;
const RDONLY: u64 = 0x8000_0000;
const APPEND: u64 = 4;
/// CREATE_ALWAYS and OPEN_EXISTING.
const CREATE_ALWAYS: u64 = 2;
const OPEN_EXISTING: u64 = 3;
/// HFILE_ERROR and INVALID_FILE_SIZE share the all-ones 32-bit answer.
const MINUS_ONE: u32 = u32::MAX;

fn imports(unicode: bool) -> [(&'static str, Vec<String>); 1] {
    let s = if unicode { "W" } else { "A" };
    [(
        "kernel32.dll",
        vec![
            format!("CreateFile{s}"),
            "WriteFile".into(),
            "ReadFile".into(),
            "GetFileSize".into(),
            "SetFilePointerEx".into(),
            "SetEndOfFile".into(),
            "GetFileTime".into(),
            "SetFileTime".into(),
            "GetFileInformationByHandle".into(),
            "FlushFileBuffers".into(),
            "CloseHandle".into(),
            format!("GetFileAttributesEx{s}"),
            format!("_lopen{s}"),
            "_lclose".into(),
            "_llseek".into(),
            "GetLastError".into(),
        ],
    )]
}

pub fn m6_file_probe(architecture: Architecture, kind: M6FileFixture, unicode: bool) -> Vec<u8> {
    use M6FileFixture as K;
    let mut p = Probe::new(architecture, unicode, &imports(unicode));
    let x86 = !p.wide;
    let guest = match kind {
        K::Size => r"C:\emumee\m6size.bin",
        K::Times => r"C:\emumee\m6time.bin",
        K::Information => r"C:\emumee\m6info.bin",
        K::Legacy => r"C:\emumee\m6legacy.bin",
        K::Denied => r"C:\emumee\m6denied.bin",
    };
    let path = p.string(guest);
    let other = p.string(r"C:\emumee\m6other.bin");
    let missing = p.string(r"C:\emumee\m6absent.bin");
    let handle = p.scratch(32);
    let count = p.scratch(16);
    let position = p.scratch(16);
    let payload = p.scratch(32);
    let readout = p.scratch(32);
    let times = p.scratch(32);
    let information = p.scratch(64);
    let attributes = p.scratch(48);
    // SetFilePointerEx takes a LARGE_INTEGER by value: two x86 stack slots.
    let seek = |distance: i64, output: u64, method: u64| {
        let mut args = vec![M(handle)];
        if x86 {
            args.extend([
                V(distance as u64 & 0xffff_ffff),
                V((distance as u64) >> 32),
            ]);
        } else {
            args.push(V(distance as u64));
        }
        args.extend([V(output), V(method)]);
        args
    };
    let create = |p: &mut Probe, name: u64, access: u64, disposition: u64| {
        p.call(
            CREATE,
            &[
                V(name),
                V(access),
                V(0),
                V(0),
                V(disposition),
                V(0x80),
                V(0),
            ],
        );
        p.opened();
        p.save(handle);
    };
    match kind {
        K::Size => {
            create(&mut p, path, RDWR, CREATE_ALWAYS);
            for index in 0..3 {
                p.set_dword(payload + index * 4, 0x44332211);
            }
            p.call(WRITE, &[M(handle), V(payload), V(10), V(count), V(0)]);
            p.eax(1);
            p.dword(count, 10);
            // The modeled file bound is far below four gibibytes, so the high
            // half is always zero when the caller asks for it.
            p.poison(count, 2);
            p.call(SIZE, &[M(handle), V(count)]);
            p.eax(10);
            p.dword(count, 0);
            p.intact(count + 4, 1);
            p.call(SIZE, &[M(handle), V(0)]);
            p.eax(10);
            // The end of the file follows the handle's own position.
            let args = seek(4, position, 0);
            p.call(SEEK, &args);
            p.eax(1);
            p.qword(position, 4);
            p.call(END_OF_FILE, &[M(handle)]);
            p.eax(1);
            p.call(SIZE, &[M(handle), V(0)]);
            p.eax(4);
            let args = seek(0, position, 2);
            p.call(SEEK, &args);
            p.eax(1);
            p.qword(position, 4);
            // Growing the file fills the new tail with zeroes.
            let args = seek(8, position, 0);
            p.call(SEEK, &args);
            p.eax(1);
            p.qword(position, 8);
            p.call(END_OF_FILE, &[M(handle)]);
            p.eax(1);
            p.call(SIZE, &[M(handle), V(0)]);
            p.eax(8);
            let args = seek(-4, position, 2);
            p.call(SEEK, &args);
            p.eax(1);
            p.qword(position, 4);
            p.poison(readout, 2);
            p.call(READ, &[M(handle), V(readout), V(4), V(count), V(0)]);
            p.eax(1);
            p.dword(count, 4);
            p.dword(readout, 0);
            p.intact(readout + 4, 1);
            // Guest bytes live in the owned filesystem, so there is no
            // write-behind cache to flush; the handle is still checked.
            p.call(FLUSH, &[M(handle)]);
            p.eax(1);
            p.call(CLOSE, &[M(handle)]);
            p.eax(1);
            p.call(FLUSH, &[M(handle)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(6);
            p.call(SIZE, &[M(handle), V(0)]);
            p.eax(MINUS_ONE);
            p.call(LAST_ERROR, &[]);
            p.eax(6);
        }
        K::Times => {
            create(&mut p, path, RDWR, CREATE_ALWAYS);
            // Before the guest sets anything the file still reports the seeded
            // filesystem time. Its value is the run's own clock, so the control
            // proves the three outputs were written rather than naming them.
            p.poison(times, 8);
            p.call(
                GET_TIME,
                &[M(handle), V(times), V(times + 8), V(times + 16)],
            );
            p.eax(1);
            for slot in 0..3u64 {
                p.dword_not(times + slot * 8, POISON);
                p.dword_not(times + slot * 8 + 4, POISON);
            }
            p.intact(times + 24, 1);
            // Three distinct times, each stored in its own slot.
            let stamps = [STAMP + 1_000_000, STAMP + 2_000_000, STAMP + 3_000_000];
            for (index, value) in stamps.iter().enumerate() {
                p.set_qword(times + index as u64 * 8, *value);
            }
            p.call(
                SET_TIME,
                &[M(handle), V(times), V(times + 8), V(times + 16)],
            );
            p.eax(1);
            p.poison(times, 8);
            p.call(
                GET_TIME,
                &[M(handle), V(times), V(times + 8), V(times + 16)],
            );
            p.eax(1);
            for (index, value) in stamps.iter().enumerate() {
                p.qword(times + index as u64 * 8, *value);
            }
            // A null pointer, a zero FILETIME and the documented "do not
            // update" sentinel all leave a time unchanged.
            p.set_qword(times + 24, 0);
            p.set_qword(times + 32, u64::MAX);
            p.call(
                SET_TIME,
                &[M(handle), V(0), V(times + 24), V(times + 32)],
            );
            p.eax(1);
            p.poison(times, 8);
            p.call(
                GET_TIME,
                &[M(handle), V(times), V(times + 8), V(times + 16)],
            );
            p.eax(1);
            for (index, value) in stamps.iter().enumerate() {
                p.qword(times + index as u64 * 8, *value);
            }
            p.call(CLOSE, &[M(handle)]);
            p.eax(1);
            // Every later metadata read observes what the guest stored.
            p.poison(attributes, 10);
            p.call(ATTRIBUTES, &[V(path), V(0), V(attributes)]);
            p.eax(1);
            p.dword(attributes, 0x80);
            for (index, value) in stamps.iter().enumerate() {
                p.qword(attributes + 4 + index as u64 * 8, *value);
            }
            p.dword(attributes + 28, 0);
            p.dword(attributes + 32, 0);
            p.intact(attributes + 36, 1);
        }
        K::Information => {
            create(&mut p, path, RDWR, CREATE_ALWAYS);
            p.set_dword(payload, 0x44332211);
            p.call(WRITE, &[M(handle), V(payload), V(3), V(count), V(0)]);
            p.eax(1);
            // Stamp the file first, so the by-handle view is checked against
            // times the guest itself chose and the same per-path times back
            // both reads.
            for slot in 0..3u64 {
                p.set_qword(times + slot * 8, STAMP + 4_000_000 + slot);
            }
            p.call(
                SET_TIME,
                &[M(handle), V(times), V(times + 8), V(times + 16)],
            );
            p.eax(1);
            let index = file_index(&guest.to_lowercase());
            p.poison(information, 14);
            p.call(INFORMATION, &[M(handle), V(information)]);
            p.eax(1);
            p.dword(information, 0x80);
            for slot in 0..3u64 {
                p.qword(information + 4 + slot * 8, STAMP + 4_000_000 + slot);
            }
            // The volume serial number is persona identity, not filesystem state.
            p.dword(information + 28, SERIAL);
            p.dword(information + 32, 0);
            p.dword(information + 36, 3);
            // Hard links are not modeled, so every file has exactly one name.
            p.dword(information + 40, 1);
            p.dword(information + 44, (index >> 32) as u32);
            p.dword(information + 48, index as u32);
            p.intact(information + 52, 1);
            p.call(CLOSE, &[M(handle)]);
            p.eax(1);
            // The index is a function of the path, so reopening the same file
            // reports the same value.
            create(&mut p, path, RDONLY, OPEN_EXISTING);
            p.call(INFORMATION, &[M(handle), V(information)]);
            p.eax(1);
            p.dword(information + 44, (index >> 32) as u32);
            p.dword(information + 48, index as u32);
            p.call(CLOSE, &[M(handle)]);
            p.eax(1);
            // A different file has a different index.
            let second = file_index(&r"C:\emumee\m6other.bin".to_lowercase());
            assert_ne!(index, second);
            create(&mut p, other, RDWR, CREATE_ALWAYS);
            p.call(INFORMATION, &[M(handle), V(information)]);
            p.eax(1);
            p.dword(information + 44, (second >> 32) as u32);
            p.dword(information + 48, second as u32);
            p.dword(information + 36, 0);
            p.call(CLOSE, &[M(handle)]);
            p.eax(1);
            p.call(INFORMATION, &[M(handle), V(information)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(6);
        }
        K::Legacy => {
            create(&mut p, path, RDWR, CREATE_ALWAYS);
            p.set_dword(payload, 0x44332211);
            p.set_dword(payload + 4, 0x88776655);
            p.call(WRITE, &[M(handle), V(payload), V(6), V(count), V(0)]);
            p.eax(1);
            p.call(CLOSE, &[M(handle)]);
            p.eax(1);
            // OF_READ. The legacy opener never creates a file.
            p.call(LOPEN, &[V(path), V(0)]);
            p.opened();
            p.save(handle);
            p.call(LSEEK, &[M(handle), V(2), V(0)]);
            p.eax(2);
            p.call(LSEEK, &[M(handle), V(0), V(2)]);
            p.eax(6);
            // _lclose answers zero on success, the opposite of CloseHandle.
            p.call(LCLOSE, &[M(handle)]);
            p.eax(0);
            p.call(LCLOSE, &[M(handle)]);
            p.eax(MINUS_ONE);
            p.call(LAST_ERROR, &[]);
            p.eax(6);
            p.call(LOPEN, &[V(missing), V(0)]);
            p.eax(MINUS_ONE);
            p.call(LAST_ERROR, &[]);
            p.eax(2);
            // OF_WRITE and OF_READWRITE reach the same model.
            for mode in [1, 2] {
                p.call(LOPEN, &[V(path), V(mode)]);
                p.opened();
                p.save(handle);
                p.call(LCLOSE, &[M(handle)]);
                p.eax(0);
            }
            p.call(LSEEK, &[V(0x1234), V(0), V(0)]);
            p.eax(MINUS_ONE);
            p.call(LAST_ERROR, &[]);
            p.eax(6);
        }
        K::Denied => {
            create(&mut p, path, RDWR, CREATE_ALWAYS);
            p.set_dword(payload, 0x44332211);
            p.call(WRITE, &[M(handle), V(payload), V(4), V(count), V(0)]);
            p.eax(1);
            p.call(CLOSE, &[M(handle)]);
            p.eax(1);
            p.set_qword(times, STAMP + 7_000_000);
            // Changing a time writes the file's directory entry, so a
            // read-only handle cannot do it, and it cannot move the end of the
            // file either.
            create(&mut p, path, RDONLY, OPEN_EXISTING);
            p.call(SET_TIME, &[M(handle), V(times), V(0), V(0)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(5);
            p.call(END_OF_FILE, &[M(handle)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(5);
            p.call(CLOSE, &[M(handle)]);
            p.eax(1);
            // Append-only access may stamp the entry and may not shorten the
            // file: SetEndOfFile requires real write access.
            create(&mut p, path, APPEND, OPEN_EXISTING);
            p.call(END_OF_FILE, &[M(handle)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(5);
            p.call(SET_TIME, &[M(handle), V(times), V(0), V(0)]);
            p.eax(1);
            p.call(CLOSE, &[M(handle)]);
            p.eax(1);
            // The refused end-of-file left the file's own bytes in place.
            p.poison(attributes, 10);
            p.call(ATTRIBUTES, &[V(path), V(0), V(attributes)]);
            p.eax(1);
            p.dword(attributes + 32, 4);
            p.qword(attributes + 4, STAMP + 7_000_000);
            // A time request against a handle that was never issued stops at
            // the handle rather than the access check.
            p.call(SET_TIME, &[V(0x1234), V(times), V(0), V(0)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(6);
        }
    }
    p.finish()
}
