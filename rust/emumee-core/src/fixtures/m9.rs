//! M9 cross-family operational controls.
//!
//! The M5-M8 control families each exercise one API partition in isolation. M9
//! is the operational gate: each control is a single generated x86/x64 program
//! that chains several modeled families together in one contained execution, so
//! the families are proved to interoperate — a value one family produces is
//! consumed by the next — not merely to answer in isolation.
//!
//! Every control is an ordinary, harmless integration program: it reserves
//! working memory, round-trips a file through the owned virtual filesystem,
//! persists and reads back a registry setting, hashes a value, or parses and
//! renders a network address. Like the M6/M7 families it decides its own
//! outcome inline — a value the model got wrong raises a breakpoint inside the
//! guest rather than being handed back for a host assertion — and returns 1
//! from its entry. No submitted-sample capture is configured; the operational
//! obligation is family interoperation, which the M8 capture obligations do not
//! cover.
use super::m6::{POISON, Probe};
use super::winhttp::Arg::{Memory as M, Value as V};
use crate::crypto::md5;
use crate::pe::Architecture;
use crate::registry::{HKCU, KEY_ALL_ACCESS, REG_DWORD};

/// Win32 allocation and file constants these controls drive.
const MEM_COMMIT_RESERVE: u64 = 0x3000;
const PAGE_READWRITE: u64 = 4;
const REGION_BYTES: u64 = 0x1000;
const GENERIC_READ: u64 = 0x8000_0000;
const OPEN_EXISTING: u64 = 3;
const FILE_ATTRIBUTE_NORMAL: u64 = 0x80;

/// CryptoAPI selectors.
const CALG_MD5: u64 = 0x8003;
const HP_HASHVAL: u64 = 2;
const PROV_RSA_FULL: u64 = 1;
const CRYPT_VERIFYCONTEXT: u64 = 0xf000_0000;

#[derive(Clone, Copy, Debug)]
pub enum M9Fixture {
    /// Allocation -> virtual filesystem -> registry: reserve a working buffer,
    /// round-trip a payload through a file, and persist and read back a
    /// registry value, all in one program.
    Provisioning,
    /// Registry -> cryptography: persist a value, read it back, and hash the
    /// exact bytes the registry returned, so the digest is computed over data
    /// the registry family produced.
    Integrity,
    /// Allocation -> network: stage an address string in a reserved buffer,
    /// then parse it with the network address model and render it back.
    Networking,
}

/// The staged guest file the provisioning control reads back. It lives in the
/// owned virtual filesystem, not on the host, and staging it is also what makes
/// its `C:\emumee` directory exist for the control to open.
pub const PROVISIONING_FILE: &str = r"C:\emumee\m9-provision.bin";
/// The staged file's exact bytes, which the control reads and checks. Shared so
/// the engine driver stages precisely what the guest verifies.
pub const PROVISIONING_SEED: &[u8] = b"emumee-m9-op";

pub fn m9_probe(architecture: Architecture, kind: M9Fixture) -> Vec<u8> {
    match kind {
        M9Fixture::Provisioning => provisioning(architecture),
        M9Fixture::Integrity => integrity(architecture),
        M9Fixture::Networking => networking(architecture),
    }
}

/// Allocation, virtual filesystem and registry in one program. The guest
/// reserves a working buffer and proves it is writable; reads a staged file
/// from the owned filesystem into a checked buffer; and persists and reads back
/// a registry value. Each family's result is checked inside the guest before
/// the next step runs. No file is written, so the control produces no artifact.
fn provisioning(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            (
                "kernel32.dll",
                vec![
                    "VirtualAlloc".into(),
                    "GetCurrentProcess".into(),
                    "WriteProcessMemory".into(),
                    "CreateFileW".into(),
                    "ReadFile".into(),
                    "CloseHandle".into(),
                ],
            ),
            (
                "advapi32.dll",
                vec![
                    "RegCreateKeyExW".into(),
                    "RegSetValueExW".into(),
                    "RegQueryValueExW".into(),
                    "RegCloseKey".into(),
                ],
            ),
        ],
    );
    const VALLOC: usize = 0;
    const CURPROC: usize = 1;
    const WPM: usize = 2;
    const CREATE: usize = 3;
    const READ: usize = 4;
    const CLOSE: usize = 5;
    const REG_CREATE: usize = 6;
    const REG_SET: usize = 7;
    const REG_QUERY: usize = 8;
    const REG_CLOSE: usize = 9;

    assert!(PROVISIONING_SEED.len() == 12, "seed is three checkable words");
    let root = if p.wide { 0xffff_ffff_8000_0001 } else { HKCU };
    let path = p.string(PROVISIONING_FILE);
    let reg_path = p.string(r"Software\EmumeeM9\Provisioning");
    let reg_name = p.string("Marker");
    let seed = p.blob(&[0x21, 0x43, 0x65, 0x87, 0x11, 0x22, 0x33, 0x44]);

    let allocation = p.scratch(8);
    let process = p.scratch(8);
    let handle = p.scratch(8);
    let count = p.scratch(16);
    let readout = p.scratch(16);
    let reg_handle = p.scratch(8);
    let disposition = p.scratch(16);
    let value = p.scratch(16);
    let value_type = p.scratch(16);
    let size = p.scratch(16);

    // Reserve a committed working buffer and prove it is a real reservation by
    // writing sentinel bytes into it through WriteProcessMemory.
    p.call(
        VALLOC,
        &[V(0), V(REGION_BYTES), V(MEM_COMMIT_RESERVE), V(PAGE_READWRITE)],
    );
    p.nonzero();
    p.save(allocation);
    p.call(CURPROC, &[]);
    p.save(process);
    p.call(WPM, &[M(process), M(allocation), V(seed), V(8), V(0)]);
    p.eax(1);

    // Open the staged file read-only and read it back into a checked buffer.
    // Reading a staged input retains no artifact, so the control stays capture
    // free while still exercising the filesystem family.
    p.call(
        CREATE,
        &[
            V(path),
            V(GENERIC_READ),
            V(0),
            V(0),
            V(OPEN_EXISTING),
            V(FILE_ATTRIBUTE_NORMAL),
            V(0),
        ],
    );
    p.opened();
    p.save(handle);
    p.poison(readout, 3);
    p.call(READ, &[M(handle), V(readout), V(PROVISIONING_SEED.len() as u64), V(count), V(0)]);
    p.eax(1);
    p.dword(count, PROVISIONING_SEED.len() as u32);
    p.check(readout, PROVISIONING_SEED, POISON.to_le_bytes()[0]);
    p.call(CLOSE, &[M(handle)]);
    p.eax(1);

    // Persist a registry value and read it back under the same open key.
    p.call(
        REG_CREATE,
        &[
            V(root),
            V(reg_path),
            V(0),
            V(0),
            V(0),
            V(KEY_ALL_ACCESS.into()),
            V(0),
            V(reg_handle),
            V(disposition),
        ],
    );
    p.eax(0);
    p.dword(disposition, 1);
    p.set_dword(value, 0x0bad_c0de);
    p.call(
        REG_SET,
        &[M(reg_handle), V(reg_name), V(0), V(REG_DWORD.into()), V(value), V(4)],
    );
    p.eax(0);
    p.set_dword(size, 4);
    p.poison(value, 1);
    p.call(
        REG_QUERY,
        &[M(reg_handle), V(reg_name), V(0), V(value_type), V(value), V(size)],
    );
    p.eax(0);
    p.dword(value_type, REG_DWORD);
    p.dword(size, 4);
    p.dword(value, 0x0bad_c0de);
    p.call(REG_CLOSE, &[M(reg_handle)]);
    p.eax(0);
    p.finish()
}

/// Registry and cryptography in one program. The value the registry returns is
/// the exact input to the hash, so the MD5 digest the guest checks proves both
/// families agreed on the same bytes.
fn integrity(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[(
            "advapi32.dll",
            vec![
                "RegCreateKeyExW".into(),
                "RegSetValueExW".into(),
                "RegQueryValueExW".into(),
                "RegCloseKey".into(),
                "CryptAcquireContextW".into(),
                "CryptCreateHash".into(),
                "CryptHashData".into(),
                "CryptGetHashParam".into(),
                "CryptDestroyHash".into(),
                "CryptReleaseContext".into(),
            ],
        )],
    );
    const REG_CREATE: usize = 0;
    const REG_SET: usize = 1;
    const REG_QUERY: usize = 2;
    const REG_CLOSE: usize = 3;
    const ACQUIRE: usize = 4;
    const CREATE_HASH: usize = 5;
    const HASH_DATA: usize = 6;
    const GET_PARAM: usize = 7;
    const DESTROY_HASH: usize = 8;
    const RELEASE: usize = 9;

    let root = if p.wide { 0xffff_ffff_8000_0001 } else { HKCU };
    let reg_path = p.string(r"Software\EmumeeM9\Integrity");
    let reg_name = p.string("Material");

    let reg_handle = p.scratch(8);
    let disposition = p.scratch(16);
    let material = p.scratch(16);
    let value_type = p.scratch(16);
    let size = p.scratch(16);
    let prov = p.scratch(16);
    let hash = p.scratch(16);
    let digest = p.scratch(32);
    let digest_size = p.scratch(16);

    const MATERIAL: u32 = 0x0a0b_0c0d;

    // Persist a value and read it back, exactly as the provisioning control
    // does, then feed those four bytes straight into the hash.
    p.call(
        REG_CREATE,
        &[
            V(root),
            V(reg_path),
            V(0),
            V(0),
            V(0),
            V(KEY_ALL_ACCESS.into()),
            V(0),
            V(reg_handle),
            V(disposition),
        ],
    );
    p.eax(0);
    p.dword(disposition, 1);
    p.set_dword(material, MATERIAL);
    p.call(
        REG_SET,
        &[M(reg_handle), V(reg_name), V(0), V(REG_DWORD.into()), V(material), V(4)],
    );
    p.eax(0);
    p.set_dword(size, 4);
    p.poison(material, 1);
    p.call(
        REG_QUERY,
        &[M(reg_handle), V(reg_name), V(0), V(value_type), V(material), V(size)],
    );
    p.eax(0);
    p.dword(value_type, REG_DWORD);
    p.dword(size, 4);
    p.dword(material, MATERIAL);

    // Hash the bytes the registry returned and check the digest.
    p.call(
        ACQUIRE,
        &[V(prov), V(0), V(0), V(PROV_RSA_FULL), V(CRYPT_VERIFYCONTEXT)],
    );
    p.eax(1);
    p.call(CREATE_HASH, &[M(prov), V(CALG_MD5), V(0), V(0), V(hash)]);
    p.eax(1);
    p.call(HASH_DATA, &[M(hash), V(material), V(4), V(0)]);
    p.eax(1);
    p.set_dword(digest_size, 32);
    p.poison(digest, 4);
    p.call(GET_PARAM, &[M(hash), V(HP_HASHVAL), V(digest), V(digest_size), V(0)]);
    p.eax(1);
    p.dword(digest_size, 16);
    p.check(digest, &md5(&MATERIAL.to_le_bytes()), POISON.to_le_bytes()[0]);
    p.call(DESTROY_HASH, &[M(hash)]);
    p.eax(1);
    p.call(RELEASE, &[M(prov), V(0)]);
    p.eax(1);
    p.call(REG_CLOSE, &[M(reg_handle)]);
    p.eax(0);
    p.finish()
}

/// Allocation and the network address model in one program. The address string
/// the network parser reads lives in a buffer the guest reserved and wrote, so
/// the parse consumes allocation-family output.
fn networking(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        false,
        &[
            (
                "ws2_32.dll",
                vec![
                    "WSAStartup".into(),
                    "WSACleanup".into(),
                    "htons".into(),
                    "inet_pton".into(),
                    "inet_ntop".into(),
                    "gethostname".into(),
                ],
            ),
            (
                "kernel32.dll",
                vec![
                    "VirtualAlloc".into(),
                    "GetCurrentProcess".into(),
                    "WriteProcessMemory".into(),
                ],
            ),
        ],
    );
    const STARTUP: usize = 0;
    const CLEANUP: usize = 1;
    const HTONS: usize = 2;
    const INET_PTON: usize = 3;
    const INET_NTOP: usize = 4;
    const GETHOSTNAME: usize = 5;
    const VALLOC: usize = 6;
    const CURPROC: usize = 7;
    const WPM: usize = 8;

    const AF_INET: u64 = 2;
    let dotted = p.ascii("192.168.1.200");
    let allocation = p.scratch(8);
    let process = p.scratch(8);
    let wsadata = p.scratch(0x200);
    let packed = p.scratch(16);
    let out = p.scratch(64);
    let host = p.scratch(64);

    // Stage the address string into a reserved buffer the network model will
    // read from.
    p.call(
        VALLOC,
        &[V(0), V(REGION_BYTES), V(MEM_COMMIT_RESERVE), V(PAGE_READWRITE)],
    );
    p.nonzero();
    p.save(allocation);
    p.call(CURPROC, &[]);
    p.save(process);
    p.call(WPM, &[M(process), M(allocation), V(dotted), V(14), V(0)]);
    p.eax(1);

    // Bring up Winsock and prove a byte-order helper before the address model.
    p.call(STARTUP, &[V(0x0202), V(wsadata)]);
    p.eax(0);
    p.dword(wsadata, 0x0202_0202);
    p.call(HTONS, &[V(0x1234)]);
    p.eax(0x3412);

    // inet_pton reads the address from the reserved buffer, and inet_ntop
    // renders the packed form back to the same dotted text.
    p.poison(packed, 1);
    p.call(INET_PTON, &[V(AF_INET), M(allocation), V(packed)]);
    p.eax(1);
    p.dword(packed, 0xc801_a8c0);
    p.poison(out, 5);
    p.call(INET_NTOP, &[V(AF_INET), V(packed), V(out), V(32)]);
    p.rax(out);
    p.check(out, b"192.168.1.200\0", POISON.to_le_bytes()[0]);

    // The host name is the persona's, which begins "DESK".
    p.call(GETHOSTNAME, &[V(host), V(64)]);
    p.eax(0);
    p.dword(host, 0x4b53_4544);
    p.call(CLEANUP, &[]);
    p.eax(0);
    p.finish()
}
