//! M6 path, search and binary-type control family: the short path a volume
//! with no 8.3 aliases reports, the extended search spelling's own argument
//! order, the documented temporary-name composition, and classification read
//! from a guest file's own headers. Two kinds must stop instead of answering.
use super::m6::{POISON, Probe, encoded};
use super::winhttp::Arg::{Memory as M, Value as V};
use crate::pe::Architecture;

#[derive(Clone, Copy, Debug)]
pub enum M6PathFixture {
    /// The short path is the long path, with the documented length query.
    ShortPath,
    /// `FindFirstFileEx` at FindExInfoStandard.
    FindExStandard,
    /// `FindFirstFileEx` at FindExInfoBasic.
    FindExBasic,
    /// `GetTempFileName` name composition and its two unique-number modes.
    TempName,
    /// `GetBinaryType` classification from the file's own headers.
    BinaryType,
    /// A short-name alias has no expansion model, so the call must stop.
    ShortNameUnsupported,
    /// An information level outside the modeled profile must stop.
    SearchLevelUnsupported,
}
/// The time the search controls stamp their own entries with. The seeded
/// filesystem time comes from the run's own clock, which a contained replay
/// cannot predict, so the find data is checked against a time the guest set.
const STAMP: u64 = 134_377_488_000_000_000;
/// The directory the search and temporary-name controls own.
const DIRECTORY: &str = r"C:\emumee\find";

const CREATE: usize = 0;
const WRITE: usize = 1;
const CLOSE: usize = 2;
const CREATE_DIRECTORY: usize = 3;
const SHORT_PATH: usize = 4;
const FIND_FIRST_EX: usize = 5;
const FIND_NEXT: usize = 6;
const FIND_CLOSE: usize = 7;
const TEMP_NAME: usize = 8;
const BINARY_TYPE: usize = 9;
const SET_TIME: usize = 10;
const LAST_ERROR: usize = 11;

fn imports(unicode: bool) -> [(&'static str, Vec<String>); 1] {
    let s = if unicode { "W" } else { "A" };
    [(
        "kernel32.dll",
        vec![
            format!("CreateFile{s}"),
            "WriteFile".into(),
            "CloseHandle".into(),
            format!("CreateDirectory{s}"),
            format!("GetShortPathName{s}"),
            // Only the generic extended spelling is declared, and it reads
            // narrow text whatever the family selects.
            "FindFirstFileEx".into(),
            "FindNextFileA".into(),
            "FindClose".into(),
            format!("GetTempFileName{s}"),
            "GetBinaryType".into(),
            "SetFileTime".into(),
            "GetLastError".into(),
        ],
    )]
}

pub fn m6_path_probe(architecture: Architecture, kind: M6PathFixture, unicode: bool) -> Vec<u8> {
    use M6PathFixture as K;
    let mut p = Probe::new(architecture, unicode, &imports(unicode));
    let staged = p.string(r"C:\emumee\m6.dat");
    let directory = p.string(DIRECTORY);
    let alpha = p.string(r"C:\emumee\find\alpha.txt");
    let beta = p.string(r"C:\emumee\find\beta.txt");
    let pattern = p.ascii(r"C:\emumee\find\*");
    let nomatch = p.ascii(r"C:\emumee\find\nomatch*");
    let alias = p.string(r"C:\emumee\M6DAT~1.DAT");
    let prefix = p.string("emumee");
    // GetBinaryType is declared only in its generic spelling, which reads
    // narrow text whatever the rest of the family selects.
    let x86_image = p.ascii(r"C:\emumee\m6x86.bin");
    let x64_image = p.ascii(r"C:\emumee\m6x64.bin");
    let narrow_staged = p.ascii(r"C:\emumee\m6.dat");
    let narrow_alpha = p.ascii(r"C:\emumee\find\alpha.txt");
    let handle = p.scratch(32);
    let count = p.scratch(32);
    let buffer = p.scratch(640);
    let find = p.scratch(1024);
    let classification = p.scratch(16);
    // The entry image FindFirstFile publishes: attributes, three times, the
    // size halves, two reserved words, then the name and the alias name.
    fn entry(p: &mut Probe, at: u64, name: &str, attributes: u32, size: u64) {
        p.dword(at, attributes);
        for slot in 0..3u64 {
            p.qword(at + 4 + slot * 8, STAMP);
        }
        p.dword(at + 28, (size >> 32) as u32);
        p.dword(at + 32, size as u32);
        p.dword(at + 36, 0);
        p.dword(at + 40, 0);
        let bytes = encoded(name, false, true);
        p.check(at + 44, &bytes, 0);
        // The name field is zero-filled past its terminator, the alias name is
        // empty, and nothing at all is written past the structure.
        p.dword(at + 44 + bytes.len().div_ceil(4) as u64 * 4, 0);
        p.dword(at + 304, 0);
        p.dword(at + 320, POISON);
    }
    /// Only the words the entry check reads need a pattern beforehand.
    fn stain(p: &mut Probe, at: u64) {
        for offset in [44, 48, 52, 56, 304, 320] {
            p.set_dword(at + offset, POISON);
        }
    }
    let create = |p: &mut Probe, name: u64, disposition: u64| {
        p.call(
            CREATE,
            &[
                V(name),
                V(0xc000_0000),
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
        K::ShortPath => {
            // A zero capacity is the documented length query: the answer counts
            // the terminator and nothing is written.
            let path = r"C:\emumee\m6.dat";
            let units = path.chars().count() as u32;
            p.poison(buffer, 16);
            p.call(SHORT_PATH, &[V(staged), V(buffer), V(0)]);
            p.eax(units + 1);
            p.intact(buffer, 16);
            // The modeled volume generates no 8.3 aliases, exactly like a
            // Windows volume with short-name creation disabled, so the short
            // path is the long path.
            p.poison(buffer, 16);
            p.call(SHORT_PATH, &[V(staged), V(buffer), V(64)]);
            p.eax(units);
            p.text(buffer, path);
            // One unit short of the terminated text is still a length query.
            p.poison(buffer, 16);
            p.call(SHORT_PATH, &[V(staged), V(buffer), V(units.into())]);
            p.eax(units + 1);
            p.intact(buffer, 16);
            // A path with no file behind it has no short form either.
            p.call(SHORT_PATH, &[V(alpha), V(buffer), V(64)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(2);
        }
        K::FindExStandard | K::FindExBasic => {
            let level = u64::from(matches!(kind, K::FindExBasic));
            p.call(CREATE_DIRECTORY, &[V(directory), V(0)]);
            p.eax(1);
            // Each entry is stamped while its handle is open, so the find data
            // is checked against a time the guest itself chose.
            p.set_qword(count + 16, STAMP);
            create(&mut p, alpha, 2);
            p.set_dword(count + 8, 0x4433_2211);
            p.call(WRITE, &[M(handle), V(count + 8), V(2), V(count), V(0)]);
            p.eax(1);
            p.call(
                SET_TIME,
                &[M(handle), V(count + 16), V(count + 16), V(count + 16)],
            );
            p.eax(1);
            p.call(CLOSE, &[M(handle)]);
            p.eax(1);
            create(&mut p, beta, 2);
            p.call(
                SET_TIME,
                &[M(handle), V(count + 16), V(count + 16), V(count + 16)],
            );
            p.eax(1);
            p.call(CLOSE, &[M(handle)]);
            p.eax(1);
            // The extended spelling takes its output buffer after the
            // information level, so the structure address is a different
            // argument than the plain spelling reads.
            stain(&mut p, find);
            p.call(
                FIND_FIRST_EX,
                &[V(pattern), V(level), V(find), V(0), V(0), V(0)],
            );
            p.opened();
            p.save(handle);
            entry(&mut p, find, "alpha.txt", 0x80, 2);
            stain(&mut p, find);
            p.call(FIND_NEXT, &[M(handle), V(find)]);
            p.eax(1);
            entry(&mut p, find, "beta.txt", 0x80, 0);
            p.call(FIND_NEXT, &[M(handle), V(find)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(18);
            p.call(FIND_CLOSE, &[M(handle)]);
            p.eax(1);
            // A closed search handle belongs to no enumeration.
            p.call(FIND_NEXT, &[M(handle), V(find)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(6);
            // A pattern that matches nothing is not a search, and issues no
            // handle at all.
            p.call(
                FIND_FIRST_EX,
                &[V(nomatch), V(level), V(find), V(0), V(0), V(0)],
            );
            p.eax(u32::MAX);
            p.call(LAST_ERROR, &[]);
            p.eax(2);
        }
        K::TempName => {
            p.call(CREATE_DIRECTORY, &[V(directory), V(0)]);
            p.eax(1);
            // A zero unique request picks a free number and leaves the empty
            // file behind; only the first three prefix characters are used.
            p.poison(buffer, 16);
            p.call(
                TEMP_NAME,
                &[V(directory), V(prefix), V(0), V(buffer)],
            );
            p.eax(1);
            p.text(buffer, &format!(r"{DIRECTORY}\emu0001.tmp"));
            // The file it created is there, so the next free number is the one
            // after it.
            p.poison(buffer, 16);
            p.call(
                TEMP_NAME,
                &[V(directory), V(prefix), V(0), V(buffer)],
            );
            p.eax(2);
            p.text(buffer, &format!(r"{DIRECTORY}\emu0002.tmp"));
            // A supplied number is used as given and creates nothing, so the
            // same number answers again.
            for _ in 0..2 {
                p.poison(buffer, 16);
                p.call(
                    TEMP_NAME,
                    &[V(directory), V(prefix), V(0x1234), V(buffer)],
                );
                p.eax(0x1234);
                p.text(buffer, &format!(r"{DIRECTORY}\emu1234.tmp"));
            }
            // A null prefix composes the name from the number alone.
            p.poison(buffer, 16);
            p.call(TEMP_NAME, &[V(directory), V(0), V(0xabcd), V(buffer)],);
            p.eax(0xabcd);
            p.text(buffer, &format!(r"{DIRECTORY}\abcd.tmp"));
            // The directory must already exist; this call never creates one.
            p.call(TEMP_NAME, &[V(alpha), V(prefix), V(0), V(buffer)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(3);
        }
        K::BinaryType => {
            // Classification comes from the guest file's own headers; no host
            // image is consulted and nothing is executed.
            p.poison(classification, 2);
            p.call(BINARY_TYPE, &[V(x86_image), V(classification)]);
            p.eax(1);
            p.dword(classification, 0);
            p.intact(classification + 4, 1);
            p.call(BINARY_TYPE, &[V(x64_image), V(classification)]);
            p.eax(1);
            p.dword(classification, 6);
            // ERROR_BAD_EXE_FORMAT covers a file that is not a PE at all.
            p.poison(classification, 1);
            p.call(BINARY_TYPE, &[V(narrow_staged), V(classification)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(193);
            p.intact(classification, 1);
            p.call(BINARY_TYPE, &[V(narrow_alpha), V(classification)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(2);
        }
        K::ShortNameUnsupported => {
            // A path naming an 8.3 alias has no expansion model here, so the
            // call stops instead of answering with the long path.
            p.call(SHORT_PATH, &[V(alias), V(buffer), V(64)]);
            p.unreachable();
        }
        K::SearchLevelUnsupported => {
            p.call(CREATE_DIRECTORY, &[V(directory), V(0)]);
            p.eax(1);
            create(&mut p, alpha, 2);
            p.call(CLOSE, &[M(handle)]);
            p.eax(1);
            // FindExInfoStandard and FindExInfoBasic are the whole modeled
            // profile; another level, a filter or extra flags must stop.
            p.call(
                FIND_FIRST_EX,
                &[V(pattern), V(2), V(find), V(0), V(0), V(0)],
            );
            p.unreachable();
        }
    }
    p.finish()
}
