//! M7 resource control family: an owned PE that carries a hand-laid `.rsrc`
//! directory and walks it through the real `FindResource*`, `LoadResource`,
//! `LockResource`, `SizeofResource`, `FreeResource` and `LoadStringW` exports,
//! deciding every outcome for itself with guest breakpoints.
use super::m6::{POISON, Probe};
use super::winhttp::Arg::{Memory as M, Value as V};
use crate::crypto::{md5, rc4};
use crate::pe::Architecture;

// Resource type ids.
const RT_STRING: u32 = 6;
const RT_RCDATA: u32 = 10;
// Language ids used in the tree.
const LANG_NEUTRAL: u32 = 0;
const LANG_ENUS: u32 = 1033;

/// RVA the resource directory is mapped at inside the probe image.
pub const RESOURCE_RVA: u64 = 0x6000;

// Resource payloads the tree carries.
const DATA_ID_NEUTRAL: &[u8] = b"RCDATA-ID-NEUTRAL";
const DATA_ID_ENUS: &[u8] = b"RCDATA-ID-ENUS-LANGUAGE";
const DATA_NAMED: &[u8] = b"RCDATA-NAMED-CONFIG";
/// The string placed at bundle index 5 (string id 5).
pub const STRING_5: &str = "EmumeeResourceString";
/// The string id `STRING_5` is stored under.
pub const STRING_ID: u32 = 5;

/// A fully resolved view of the built resource tree: where each data entry and
/// its bytes live, so a caller can assert exact handles and sizes.
pub struct ResourceTree {
    pub blob: Vec<u8>,
    /// Data-entry offsets, relative to the resource base.
    pub entry_id_neutral: u32,
    pub entry_id_enus: u32,
    pub entry_named: u32,
    /// Raw-byte RVAs (image relative) and sizes.
    pub data_id_neutral_rva: u32,
    pub data_id_neutral_size: u32,
    pub data_named_rva: u32,
    pub data_named_size: u32,
}

impl ResourceTree {
    /// `HRSRC` a `FindResource` call returns for a data entry.
    pub fn hrsrc(&self, base: u64, entry_offset: u32) -> u64 {
        base + RESOURCE_RVA + entry_offset as u64
    }
}

fn put16(buf: &mut [u8], at: usize, value: u16) {
    buf[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(buf: &mut [u8], at: usize, value: u32) {
    buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// The string-table bundle for ids 0..=15: 16 length-prefixed UTF-16 strings,
/// with `STRING_5` at index `STRING_ID`.
fn string_bundle() -> Vec<u8> {
    let mut bytes = Vec::new();
    for index in 0..16u32 {
        if index == STRING_ID {
            let units: Vec<u16> = STRING_5.encode_utf16().collect();
            bytes.extend((units.len() as u16).to_le_bytes());
            bytes.extend(units.iter().flat_map(|u| u.to_le_bytes()));
        } else {
            bytes.extend(0u16.to_le_bytes());
        }
    }
    bytes
}

/// Build the resource blob mapped at [`RESOURCE_RVA`]. The tree holds, under
/// `RT_RCDATA`, id 101 (neutral + en-US languages) and the named resource
/// "CONFIG" (en-US), and under `RT_STRING`, bundle 1 (neutral) carrying the
/// string ids 0..=15.
pub fn resource_tree() -> ResourceTree {
    let config = "CONFIG";
    let bundle = string_bundle();

    // Fixed layout, assigned in emission order. Directory header is 16 bytes,
    // each entry 8 bytes; name strings are WORD-length-prefixed UTF-16.
    let root = 0u32; // type level: ids 6, 10
    let str_name = root + 16 + 2 * 8; // RT_STRING name level: id 1
    let rc_name = str_name + 16 + 8; // RT_RCDATA name level: "CONFIG", id 101
    let str1_lang = rc_name + 16 + 2 * 8; // RT_STRING/1 lang level: neutral
    let config_lang = str1_lang + 16 + 8; // RT_RCDATA/CONFIG lang level: en-US
    let id101_lang = config_lang + 16 + 8; // RT_RCDATA/101 lang level: neutral, en-US
    let name_config = id101_lang + 16 + 2 * 8; // "CONFIG" dir string
    let config_len = 2 + config.len() as u32 * 2;
    // Data entries (16 bytes each), 4-byte aligned.
    let entries = (name_config + config_len).next_multiple_of(4);
    let entry_id_neutral = entries;
    let entry_id_enus = entry_id_neutral + 16;
    let entry_named = entry_id_enus + 16;
    let entry_string = entry_named + 16;
    // Raw data, 4-byte aligned.
    let data = (entry_string + 16).next_multiple_of(4);
    let data_id_neutral = data;
    let data_id_enus = (data_id_neutral + DATA_ID_NEUTRAL.len() as u32).next_multiple_of(4);
    let data_named = (data_id_enus + DATA_ID_ENUS.len() as u32).next_multiple_of(4);
    let data_string = (data_named + DATA_NAMED.len() as u32).next_multiple_of(4);
    let total = (data_string + bundle.len() as u32).next_multiple_of(4);

    let mut blob = vec![0u8; total as usize];

    let dir = |blob: &mut [u8], at: u32, named: u16, ids: u16| {
        put16(blob, at as usize + 12, named);
        put16(blob, at as usize + 14, ids);
    };
    // entry at directory `at`, slot `n`: name/id word and child offset word.
    let entry = |blob: &mut [u8], at: u32, n: u32, name: u32, child: u32| {
        let base = at as usize + 16 + n as usize * 8;
        put32(blob, base, name);
        put32(blob, base + 4, child);
    };
    const SUBDIR: u32 = 0x8000_0000;
    const NAMED: u32 = 0x8000_0000;

    // Type level: RT_STRING (6) then RT_RCDATA (10), ascending ids.
    dir(&mut blob, root, 0, 2);
    entry(&mut blob, root, 0, RT_STRING, str_name | SUBDIR);
    entry(&mut blob, root, 1, RT_RCDATA, rc_name | SUBDIR);

    // RT_STRING name level: bundle id 1.
    dir(&mut blob, str_name, 0, 1);
    entry(&mut blob, str_name, 0, 1, str1_lang | SUBDIR);

    // RT_RCDATA name level: named "CONFIG" first, then id 101.
    dir(&mut blob, rc_name, 1, 1);
    entry(&mut blob, rc_name, 0, name_config | NAMED, config_lang | SUBDIR);
    entry(&mut blob, rc_name, 1, 101, id101_lang | SUBDIR);

    // Language levels.
    dir(&mut blob, str1_lang, 0, 1);
    entry(&mut blob, str1_lang, 0, LANG_NEUTRAL, entry_string);

    dir(&mut blob, config_lang, 0, 1);
    entry(&mut blob, config_lang, 0, LANG_ENUS, entry_named);

    dir(&mut blob, id101_lang, 0, 2);
    entry(&mut blob, id101_lang, 0, LANG_NEUTRAL, entry_id_neutral);
    entry(&mut blob, id101_lang, 1, LANG_ENUS, entry_id_enus);

    // "CONFIG" directory string: WORD length then UTF-16 units.
    put16(&mut blob, name_config as usize, config.len() as u16);
    for (index, unit) in config.encode_utf16().enumerate() {
        put16(&mut blob, name_config as usize + 2 + index * 2, unit);
    }

    // Data entries: OffsetToData (image RVA), Size, CodePage, Reserved.
    let data_entry = |blob: &mut [u8], at: u32, rva: u32, size: u32| {
        put32(blob, at as usize, RESOURCE_RVA as u32 + rva);
        put32(blob, at as usize + 4, size);
    };
    data_entry(&mut blob, entry_id_neutral, data_id_neutral, DATA_ID_NEUTRAL.len() as u32);
    data_entry(&mut blob, entry_id_enus, data_id_enus, DATA_ID_ENUS.len() as u32);
    data_entry(&mut blob, entry_named, data_named, DATA_NAMED.len() as u32);
    data_entry(&mut blob, entry_string, data_string, bundle.len() as u32);

    // Raw bytes.
    let place = |blob: &mut [u8], at: u32, bytes: &[u8]| {
        blob[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
    };
    place(&mut blob, data_id_neutral, DATA_ID_NEUTRAL);
    place(&mut blob, data_id_enus, DATA_ID_ENUS);
    place(&mut blob, data_named, DATA_NAMED);
    place(&mut blob, data_string, &bundle);

    ResourceTree {
        blob,
        entry_id_neutral,
        entry_id_enus,
        entry_named,
        data_id_neutral_rva: RESOURCE_RVA as u32 + data_id_neutral,
        data_id_neutral_size: DATA_ID_NEUTRAL.len() as u32,
        data_named_rva: RESOURCE_RVA as u32 + data_named,
        data_named_size: DATA_NAMED.len() as u32,
    }
}

#[derive(Clone, Copy, Debug)]
pub enum M7ResourceFixture {
    /// Locate a resource by integer id, load, lock, size and free it.
    ById,
    /// Locate a resource by string name through the `Ex` spelling.
    ByName,
    /// Load a string from the string-table bundle.
    LoadString,
    /// A missing type, name and language each fail with their own error.
    Missing,
}

fn imports() -> [(&'static str, Vec<String>); 1] {
    [(
        "kernel32.dll",
        vec![
            "FindResourceW".into(),      // 0
            "FindResourceExW".into(),    // 1
            "LoadResource".into(),       // 2
            "LockResource".into(),       // 3
            "SizeofResource".into(),     // 4
            "FreeResource".into(),       // 5
            "LoadStringW".into(),        // 6
            "GetLastError".into(),       // 7
        ],
    )]
}
const FIND: usize = 0;
const FIND_EX: usize = 1;
const LOAD: usize = 2;
const LOCK: usize = 3;
const SIZEOF: usize = 4;
const FREE: usize = 5;
const LOAD_STRING: usize = 6;
const LAST_ERROR: usize = 7;

pub fn m7_resource_probe(architecture: Architecture, kind: M7ResourceFixture) -> Vec<u8> {
    use M7ResourceFixture as K;
    // Resources read the W selectors, so the probe always runs wide.
    let mut p = Probe::new(architecture, true, &imports());
    let tree = resource_tree();
    p.resources(RESOURCE_RVA, &tree.blob);
    let base = p.base;
    // MAKEINTRESOURCE(n): a bare integer in the pointer slot.
    let rt_rcdata = RT_RCDATA as u64;
    let hrsrc = p.scratch(16);
    let hglobal = p.scratch(16);
    let buffer = p.scratch(0x80);

    match kind {
        K::ById => {
            // FindResourceW(module=self, name=101, type=RT_RCDATA): self module
            // is the primary image, passed as NULL here.
            p.call(FIND, &[V(0), V(101), V(rt_rcdata)]);
            let entry = tree.hrsrc(base, tree.entry_id_neutral);
            p.rax(entry);
            p.save(hrsrc);
            // LoadResource yields the mapped first byte.
            p.call(LOAD, &[V(0), M(hrsrc)]);
            let data = base + tree.data_id_neutral_rva as u64;
            p.rax(data);
            p.save(hglobal);
            // LockResource is identity.
            p.call(LOCK, &[M(hglobal)]);
            p.rax(data);
            // SizeofResource reports the entry size.
            p.call(SIZEOF, &[V(0), M(hrsrc)]);
            p.eax(tree.data_id_neutral_size);
            // The loaded bytes are the resource payload.
            p.check(data, DATA_ID_NEUTRAL, 0);
            // FreeResource is a no-op and reports FALSE.
            p.call(FREE, &[M(hglobal)]);
            p.eax(0);
            // FindResourceExW selecting en-US reaches the other-language entry.
            p.call(FIND_EX, &[V(0), V(rt_rcdata), V(101), V(LANG_ENUS as u64)]);
            p.rax(tree.hrsrc(base, tree.entry_id_enus));
        }
        K::ByName => {
            let name = p.string("CONFIG");
            // FindResourceExW(type, name="CONFIG", en-US).
            p.call(FIND_EX, &[V(0), V(rt_rcdata), V(name), V(LANG_ENUS as u64)]);
            let entry = tree.hrsrc(base, tree.entry_named);
            p.rax(entry);
            p.save(hrsrc);
            p.call(SIZEOF, &[V(0), M(hrsrc)]);
            p.eax(tree.data_named_size);
            p.call(LOAD, &[V(0), M(hrsrc)]);
            let data = base + tree.data_named_rva as u64;
            p.rax(data);
            p.check(data, DATA_NAMED, 0);
            // A lowercase name still matches: resource names fold case.
            let lower = p.string("config");
            p.call(FIND_EX, &[V(0), V(rt_rcdata), V(lower), V(LANG_ENUS as u64)]);
            p.rax(entry);
        }
        K::LoadString => {
            // LoadStringW(hInstance=self, id, buffer, cch).
            p.poison(buffer, 0x80 / 4);
            p.call(LOAD_STRING, &[V(0), V(STRING_ID as u64), V(buffer), V(0x40)]);
            p.eax(STRING_5.chars().count() as u32);
            p.text(buffer, STRING_5);
        }
        K::Missing => {
            // A type that is not present fails with ERROR_RESOURCE_TYPE_NOT_FOUND.
            p.call(FIND, &[V(0), V(101), V(99)]);
            p.rax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(1813);
            // A present type with an absent name fails with its own error.
            p.call(FIND, &[V(0), V(4242), V(rt_rcdata)]);
            p.rax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(1814);
            // LoadStringW for an id in no bundle fails too.
            p.call(LOAD_STRING, &[V(0), V(5000), V(buffer), V(0x40)]);
            p.eax(0);
        }
    }
    p.finish()
}

// CryptoAPI algorithm ids and selectors the controls use.
const CALG_MD5: u64 = 0x8003;
const CALG_RC4: u64 = 0x6801;
const HP_HASHVAL: u64 = 2;
const HP_HASHSIZE: u64 = 4;
const CRYPT_STRING_BASE64: u64 = 1;
const CRYPT_STRING_HEX: u64 = 4;
const PROV_RSA_FULL: u64 = 1;
const CRYPT_VERIFYCONTEXT: u64 = 0xF000_0000;

#[derive(Clone, Copy, Debug)]
pub enum M7CryptoFixture {
    /// Acquire a context, hash "abc" with MD5 and read the digest back.
    Hash,
    /// Draw a deterministic random stream from the three providers.
    Random,
    /// Base64- and hex-decode a payload through CryptStringToBinary.
    Decode,
    /// Derive an RC4 key from a hash and decrypt a buffer in place.
    Rc4,
    /// Open a BCrypt provider, read a property, and open/free an NCrypt one.
    Cng,
}

/// Fixed-seed SplitMix64, mirroring the model random stream so a control can
/// assert the exact bytes the providers return.
fn splitmix(state: &mut u64) -> [u8; 8] {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (z ^ (z >> 31)).to_le_bytes()
}

pub fn m7_crypto_probe(architecture: Architecture, kind: M7CryptoFixture) -> Vec<u8> {
    use M7CryptoFixture as K;
    match kind {
        K::Hash => crypto_hash(architecture),
        K::Random => crypto_random(architecture),
        K::Decode => crypto_decode(architecture),
        K::Rc4 => crypto_rc4(architecture),
        K::Cng => crypto_cng(architecture),
    }
}

fn advapi(exports: &[&str]) -> [(&'static str, Vec<String>); 1] {
    [("advapi32.dll", exports.iter().map(|s| s.to_string()).collect())]
}

fn crypto_hash(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &advapi(&[
            "CryptAcquireContextW",
            "CryptCreateHash",
            "CryptHashData",
            "CryptGetHashParam",
            "CryptDestroyHash",
            "CryptReleaseContext",
        ]),
    );
    const ACQUIRE: usize = 0;
    const CREATE: usize = 1;
    const HASHDATA: usize = 2;
    const GETPARAM: usize = 3;
    const DESTROY: usize = 4;
    const RELEASE: usize = 5;
    let prov = p.scratch(16);
    let hash = p.scratch(16);
    let size = p.scratch(16);
    let out = p.scratch(64);
    let data = p.ascii("abc");

    p.call(ACQUIRE, &[V(prov), V(0), V(0), V(PROV_RSA_FULL), V(CRYPT_VERIFYCONTEXT)]);
    p.eax(1);
    p.call(CREATE, &[M(prov), V(CALG_MD5), V(0), V(0), V(hash)]);
    p.eax(1);
    p.call(HASHDATA, &[M(hash), V(data), V(3), V(0)]);
    p.eax(1);
    // HP_HASHSIZE reports the digest length.
    p.set_dword(size, 64);
    p.call(GETPARAM, &[M(hash), V(HP_HASHSIZE), V(out), V(size), V(0)]);
    p.eax(1);
    p.dword(out, 16);
    p.dword(size, 4);
    // HP_HASHVAL is the MD5 digest of the fed bytes.
    p.set_dword(size, 64);
    p.poison(out, 8);
    p.call(GETPARAM, &[M(hash), V(HP_HASHVAL), V(out), V(size), V(0)]);
    p.eax(1);
    p.dword(size, 16);
    p.check(out, &md5(b"abc"), POISON.to_le_bytes()[0]);
    p.intact(out + 16, 1);
    p.call(DESTROY, &[M(hash)]);
    p.eax(1);
    p.call(RELEASE, &[M(prov), V(0)]);
    p.eax(1);
    p.finish()
}

fn crypto_random(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            (
                "advapi32.dll",
                vec![
                    "CryptAcquireContextW".into(),
                    "CryptGenRandom".into(),
                    "SystemFunction036".into(),
                ],
            ),
            ("bcryptprimitives.dll", vec!["ProcessPrng".into()]),
        ],
    );
    const ACQUIRE: usize = 0;
    const GEN: usize = 1;
    const RTLGEN: usize = 2;
    const PROCESSPRNG: usize = 3;
    let prov = p.scratch(16);
    let a = p.scratch(16);
    let b = p.scratch(16);
    let c = p.scratch(16);

    // The three providers share one deterministic stream, so the exact bytes
    // are predictable and identical on replay.
    let mut state = 0u64;
    let first = splitmix(&mut state);
    let second = splitmix(&mut state);
    let third = splitmix(&mut state);

    p.call(ACQUIRE, &[V(prov), V(0), V(0), V(PROV_RSA_FULL), V(CRYPT_VERIFYCONTEXT)]);
    p.eax(1);
    p.poison(a, 2);
    // CryptGenRandom(hProv, dwLen, pbBuffer).
    p.call(GEN, &[M(prov), V(8), V(a)]);
    p.eax(1);
    p.check(a, &first, POISON.to_le_bytes()[0]);
    p.poison(b, 2);
    // SystemFunction036(pbBuffer, ulLen).
    p.call(RTLGEN, &[V(b), V(8)]);
    p.eax(1);
    p.check(b, &second, POISON.to_le_bytes()[0]);
    p.poison(c, 2);
    // ProcessPrng(pbData, cbData).
    p.call(PROCESSPRNG, &[V(c), V(8)]);
    p.eax(1);
    p.check(c, &third, POISON.to_le_bytes()[0]);
    p.finish()
}

fn crypto_decode(architecture: Architecture) -> Vec<u8> {
    let mut p =
        Probe::new(architecture, true, &[("crypt32.dll", vec!["CryptStringToBinaryA".into()])]);
    const STB: usize = 0;
    let out = p.scratch(64);
    let outlen = p.scratch(16);
    let skip = p.scratch(16);
    let flags = p.scratch(16);
    let base64 = p.ascii("YWJj");
    let hexstr = p.ascii("616263");

    // Base64 "YWJj" decodes to "abc".
    p.set_dword(outlen, 64);
    p.poison(out, 1);
    p.call(STB, &[V(base64), V(0), V(CRYPT_STRING_BASE64), V(out), V(outlen), V(skip), V(flags)]);
    p.eax(1);
    p.dword(outlen, 3);
    p.check(out, b"abc", POISON.to_le_bytes()[0]);
    // Hex "616263" decodes to the same bytes.
    p.set_dword(outlen, 64);
    p.poison(out, 1);
    p.call(STB, &[V(hexstr), V(0), V(CRYPT_STRING_HEX), V(out), V(outlen), V(skip), V(flags)]);
    p.eax(1);
    p.dword(outlen, 3);
    p.check(out, b"abc", POISON.to_le_bytes()[0]);
    p.finish()
}

fn crypto_rc4(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &advapi(&[
            "CryptAcquireContextW",
            "CryptCreateHash",
            "CryptHashData",
            "CryptDeriveKey",
            "CryptDecrypt",
            "CryptDestroyHash",
            "CryptReleaseContext",
        ]),
    );
    const ACQUIRE: usize = 0;
    const CREATE: usize = 1;
    const HASHDATA: usize = 2;
    const DERIVE: usize = 3;
    const DECRYPT: usize = 4;
    const DESTROY: usize = 5;
    const RELEASE: usize = 6;
    let prov = p.scratch(16);
    let hash = p.scratch(16);
    let key = p.scratch(16);
    let buf = p.scratch(64);
    let len = p.scratch(16);
    let keydata = p.ascii("secretkey");

    let plaintext = b"EMUMEE RC4 PAYLOAD 12";
    let material = md5(b"secretkey");
    let cipher = rc4(&material, plaintext);

    p.call(ACQUIRE, &[V(prov), V(0), V(0), V(PROV_RSA_FULL), V(CRYPT_VERIFYCONTEXT)]);
    p.eax(1);
    p.call(CREATE, &[M(prov), V(CALG_MD5), V(0), V(0), V(hash)]);
    p.eax(1);
    p.call(HASHDATA, &[M(hash), V(keydata), V(9), V(0)]);
    p.eax(1);
    p.call(DERIVE, &[M(prov), V(CALG_RC4), M(hash), V(0), V(key)]);
    p.eax(1);
    // Load the ciphertext into the buffer, four bytes at a time.
    for (index, chunk) in cipher.chunks(4).enumerate() {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        p.set_dword(buf + index as u64 * 4, u32::from_le_bytes(word));
    }
    p.set_dword(len, cipher.len() as u32);
    p.call(DECRYPT, &[M(key), V(0), V(1), V(0), V(buf), V(len)]);
    p.eax(1);
    // In-place decryption recovered the plaintext.
    p.check(buf, plaintext, 0);
    p.call(DESTROY, &[M(hash)]);
    p.eax(1);
    p.call(RELEASE, &[M(prov), V(0)]);
    p.eax(1);
    p.finish()
}

fn crypto_cng(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            (
                "bcrypt.dll",
                vec![
                    "BCryptOpenAlgorithmProvider".into(),
                    "BCryptGetProperty".into(),
                    "BCryptCloseAlgorithmProvider".into(),
                ],
            ),
            ("ncrypt.dll", vec!["NCryptOpenStorageProvider".into(), "NCryptFreeObject".into()]),
        ],
    );
    const BOPEN: usize = 0;
    const BGET: usize = 1;
    const BCLOSE: usize = 2;
    const NOPEN: usize = 3;
    const NFREE: usize = 4;
    let alg = p.scratch(16);
    let out = p.scratch(16);
    let res = p.scratch(16);
    let nprov = p.scratch(16);
    let algname = p.string("SHA256");
    let property = p.string("HashDigestLength");
    let provname = p.string("Microsoft Software Key Storage Provider");

    // STATUS_SUCCESS is zero for the CNG surface.
    p.call(BOPEN, &[V(alg), V(algname), V(0), V(0)]);
    p.eax(0);
    p.set_dword(res, 0);
    p.poison(out, 1);
    p.call(BGET, &[M(alg), V(property), V(out), V(4), V(res), V(0)]);
    p.eax(0);
    p.dword(out, 32);
    p.dword(res, 4);
    p.call(BCLOSE, &[M(alg), V(0)]);
    p.eax(0);
    p.call(NOPEN, &[V(nprov), V(provname), V(0)]);
    p.eax(0);
    p.call(NFREE, &[M(nprov)]);
    p.eax(0);
    p.finish()
}

#[derive(Clone, Copy, Debug)]
pub enum M7PathFixture {
    /// Pointer-returning and value shlwapi helpers (wide).
    Query,
    /// In-place path edits (narrow), each verified with lstrcmp.
    Edit,
}

/// Write `text` (with terminator) into a scratch buffer at run time, so a
/// mutating path call has a known, writable input.
fn load_str(p: &mut Probe, addr: u64, text: &str, wide: bool) {
    let bytes = super::m6::encoded(text, wide, true);
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        p.set_dword(addr + index as u64 * 4, u32::from_le_bytes(word));
    }
}

pub fn m7_path_probe(architecture: Architecture, kind: M7PathFixture) -> Vec<u8> {
    match kind {
        M7PathFixture::Query => path_query(architecture),
        M7PathFixture::Edit => path_edit(architecture),
    }
}

fn path_query(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[(
            "shlwapi.dll",
            vec![
                "PathFindFileNameW".into(),
                "PathFindExtensionW".into(),
                "PathIsRelativeW".into(),
                "StrStrW".into(),
                "StrStrIW".into(),
                "StrCmpIW".into(),
            ],
        )],
    );
    const FINDFILE: usize = 0;
    const FINDEXT: usize = 1;
    const ISREL: usize = 2;
    const STRSTR: usize = 3;
    const STRSTRI: usize = 4;
    const STRCMPI: usize = 5;

    let path = p.string(r"C:\Users\Alex\file.dat");
    // "...\file.dat": last separator at index 13, extension dot at index 18.
    p.call(FINDFILE, &[V(path)]);
    p.rax(path + 14 * 2);
    p.call(FINDEXT, &[V(path)]);
    p.rax(path + 18 * 2);

    p.call(ISREL, &[V(path)]);
    p.eax(0);
    let relative = p.string(r"Users\Alex");
    p.call(ISREL, &[V(relative)]);
    p.eax(1);

    let hay = p.string("malware.exe payload");
    let needle = p.string("payload");
    p.call(STRSTR, &[V(hay), V(needle)]);
    p.rax(hay + 12 * 2);
    let missing = p.string("zzz");
    p.call(STRSTR, &[V(hay), V(missing)]);
    p.rax(0);
    let upper = p.string("PAYLOAD");
    p.call(STRSTRI, &[V(hay), V(upper)]);
    p.rax(hay + 12 * 2);

    let a = p.string("Hello");
    let b = p.string("hello");
    p.call(STRCMPI, &[V(a), V(b)]);
    p.eax(0);
    let world = p.string("world");
    p.call(STRCMPI, &[V(a), V(world)]);
    p.eax(u32::MAX);
    p.finish()
}

fn path_edit(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        false,
        &[
            (
                "shlwapi.dll",
                vec![
                    "PathAddBackslashA".into(),
                    "PathAppendA".into(),
                    "PathCanonicalizeA".into(),
                    "PathRemoveExtensionA".into(),
                    "PathRemoveFileSpecA".into(),
                    "PathRenameExtensionA".into(),
                    "PathStripPathA".into(),
                ],
            ),
            ("kernel32.dll", vec!["lstrcmpA".into()]),
        ],
    );
    const ADDBS: usize = 0;
    const APPEND: usize = 1;
    const CANON: usize = 2;
    const RMEXT: usize = 3;
    const RMSPEC: usize = 4;
    const RENEXT: usize = 5;
    const STRIP: usize = 6;
    const CMP: usize = 7;

    let expect = |p: &mut Probe, buf: u64, text: &str| {
        let s = p.ascii(text);
        p.call(CMP, &[V(buf), V(s)]);
        p.eax(0);
    };

    let buf = p.scratch(64);
    load_str(&mut p, buf, r"C:\dir", false);
    p.call(ADDBS, &[V(buf)]);
    expect(&mut p, buf, r"C:\dir\");

    let buf = p.scratch(64);
    load_str(&mut p, buf, r"C:\dir", false);
    let more = p.ascii("file.txt");
    p.call(APPEND, &[V(buf), V(more)]);
    p.eax(1);
    expect(&mut p, buf, r"C:\dir\file.txt");

    let dst = p.scratch(64);
    let src = p.ascii(r"C:\a\b\..\c");
    p.call(CANON, &[V(dst), V(src)]);
    p.eax(1);
    expect(&mut p, dst, r"C:\a\c");

    let buf = p.scratch(64);
    load_str(&mut p, buf, "report.txt", false);
    p.call(RMEXT, &[V(buf)]);
    expect(&mut p, buf, "report");

    let buf = p.scratch(64);
    load_str(&mut p, buf, r"C:\dir\sub\f.bin", false);
    p.call(RMSPEC, &[V(buf)]);
    p.eax(1);
    expect(&mut p, buf, r"C:\dir\sub");

    let buf = p.scratch(64);
    load_str(&mut p, buf, "data.old", false);
    let ext = p.ascii(".new");
    p.call(RENEXT, &[V(buf), V(ext)]);
    p.eax(1);
    expect(&mut p, buf, "data.new");

    let buf = p.scratch(64);
    load_str(&mut p, buf, r"C:\dir\only.txt", false);
    p.call(STRIP, &[V(buf)]);
    expect(&mut p, buf, "only.txt");

    p.finish()
}

#[derive(Clone, Copy, Debug)]
pub enum M7ComFixture {
    /// Activation, vtable identity, refcount lifetime and a rejected IID.
    Activation,
    /// The WMI locator/services/enumerator chain through real vtables.
    Wbem,
    /// BSTR allocation, length, release and VARIANT initialization.
    Bstr,
    /// Deterministic CoCreateGuid and its string form.
    Guid,
    /// Deterministic UuidCreate and its RPC string form.
    Uuid,
    /// Known folders, directory trees, argv splitting, observed execution and
    /// an IMalloc round trip.
    Shell,
}

/// A GUID in its in-memory little-endian layout.
fn guid_bytes(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend(d1.to_le_bytes());
    bytes.extend(d2.to_le_bytes());
    bytes.extend(d3.to_le_bytes());
    bytes.extend(d4);
    bytes
}

fn clsid_wbem_locator() -> Vec<u8> {
    guid_bytes(0x4590F811, 0x1D3A, 0x11D0, [0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24])
}
fn iid_wbem_locator() -> Vec<u8> {
    guid_bytes(0xDC12A687, 0x737F, 0x11CF, [0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24])
}
fn iid_unknown() -> Vec<u8> {
    guid_bytes(0, 0, 0, [0xC0, 0, 0, 0, 0, 0, 0, 0x46])
}

// Vtable indices the model publishes.
const V_QUERY_INTERFACE: usize = 0;
const V_ADDREF: usize = 1;
const V_RELEASE: usize = 2;
const V_CONNECT_SERVER: usize = 3;
const V_EXEC_QUERY: usize = 20;
const V_ENUM_NEXT: usize = 4;
const V_MALLOC_ALLOC: usize = 3;
const V_MALLOC_FREE: usize = 5;

const CLSCTX_INPROC_SERVER: u64 = 1;
const E_NOINTERFACE: u32 = 0x8000_4002;
const WBEM_S_FALSE: u32 = 1;

pub fn m7_com_probe(architecture: Architecture, kind: M7ComFixture) -> Vec<u8> {
    use M7ComFixture as K;
    match kind {
        K::Activation => com_activation(architecture),
        K::Wbem => com_wbem(architecture),
        K::Bstr => com_bstr(architecture),
        K::Guid => com_guid(architecture),
        K::Uuid => com_uuid(architecture),
        K::Shell => com_shell(architecture),
    }
}

fn com_activation(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[(
            "ole32.dll",
            vec![
                "CoInitializeEx".into(),
                "CoCreateInstance".into(),
                "CoUninitialize".into(),
            ],
        )],
    );
    const COINIT: usize = 0;
    const CREATE: usize = 1;
    const COUNINIT: usize = 2;
    let clsid = p.blob(&clsid_wbem_locator());
    let iid = p.blob(&iid_wbem_locator());
    let unknown = p.blob(&iid_unknown());
    let bogus = p.blob(&guid_bytes(0xDEADBEEF, 1, 2, [3, 4, 5, 6, 7, 8, 9, 10]));
    let locator = p.scratch(16);
    let other = p.scratch(16);

    // The first apartment initialize succeeds; a nested one reports S_FALSE.
    p.call(COINIT, &[V(0), V(0)]);
    p.eax(0);
    p.call(COINIT, &[V(0), V(0)]);
    p.eax(1);

    p.call(CREATE, &[V(clsid), V(0), V(CLSCTX_INPROC_SERVER), V(iid), V(locator)]);
    p.eax(0);
    // A fresh object starts at one reference.
    p.call_vtable(V_ADDREF, &[M(locator)]);
    p.eax(2);
    p.call_vtable(V_RELEASE, &[M(locator)]);
    p.eax(1);

    // QueryInterface for an interface the object exposes answers the same
    // pointer and takes its own reference.
    p.poison(other, 2);
    p.call_vtable(V_QUERY_INTERFACE, &[M(locator), V(unknown), V(other)]);
    p.eax(0);
    // AddRef through the queried pointer proves it is the same object: the
    // count continues from two rather than restarting.
    p.call_vtable(V_ADDREF, &[M(other)]);
    p.eax(3);
    p.call_vtable(V_RELEASE, &[M(other)]);
    p.eax(2);
    p.call_vtable(V_RELEASE, &[M(locator)]);
    p.eax(1);
    p.call_vtable(V_RELEASE, &[M(locator)]);
    p.eax(0);

    // An interface the class does not expose is refused and the out pointer is
    // cleared rather than left stale.
    p.set_dword(other, 0x1234);
    p.call(CREATE, &[V(clsid), V(0), V(CLSCTX_INPROC_SERVER), V(bogus), V(other)]);
    p.eax(E_NOINTERFACE);
    p.dword(other, 0);

    p.call(COUNINIT, &[]);
    p.call(COUNINIT, &[]);
    p.finish()
}

fn com_wbem(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            ("ole32.dll", vec!["CoInitializeEx".into(), "CoCreateInstance".into()]),
            ("oleaut32.dll", vec!["SysAllocString".into()]),
        ],
    );
    const COINIT: usize = 0;
    const CREATE: usize = 1;
    const SYSALLOC: usize = 2;
    let clsid = p.blob(&clsid_wbem_locator());
    let iid = p.blob(&iid_wbem_locator());
    let namespace = p.string(r"ROOT\CIMV2");
    let language = p.string("WQL");
    let query = p.string("SELECT * FROM Win32_Process");
    let locator = p.scratch(16);
    let services = p.scratch(16);
    let enumerator = p.scratch(16);
    let bstr_ns = p.scratch(16);
    let bstr_lang = p.scratch(16);
    let bstr_query = p.scratch(16);
    let objects = p.scratch(32);
    let returned = p.scratch(16);

    p.call(COINIT, &[V(0), V(0)]);
    p.eax(0);
    p.call(CREATE, &[V(clsid), V(0), V(CLSCTX_INPROC_SERVER), V(iid), V(locator)]);
    p.eax(0);

    p.call(SYSALLOC, &[V(namespace)]);
    p.nonzero();
    p.save(bstr_ns);
    // ConnectServer(this, resource, user, password, locale, flags, authority,
    // ctx, ppNamespace).
    p.call_vtable(
        V_CONNECT_SERVER,
        &[
            M(locator),
            M(bstr_ns),
            V(0),
            V(0),
            V(0),
            V(0),
            V(0),
            V(0),
            V(services),
        ],
    );
    p.eax(0);

    p.call(SYSALLOC, &[V(language)]);
    p.save(bstr_lang);
    p.call(SYSALLOC, &[V(query)]);
    p.save(bstr_query);
    // ExecQuery(this, language, query, flags, ctx, ppEnum).
    p.call_vtable(
        V_EXEC_QUERY,
        &[M(services), M(bstr_lang), M(bstr_query), V(0), V(0), V(enumerator)],
    );
    p.eax(0);

    // The modeled enumeration is empty: Next reports WBEM_S_FALSE and returns
    // no objects.
    p.set_dword(returned, 0xFFFF_FFFF);
    p.call_vtable(
        V_ENUM_NEXT,
        &[M(enumerator), V(0xFFFF_FFFF), V(1), V(objects), V(returned)],
    );
    p.eax(WBEM_S_FALSE);
    p.dword(returned, 0);

    p.call_vtable(V_RELEASE, &[M(enumerator)]);
    p.eax(0);
    p.call_vtable(V_RELEASE, &[M(services)]);
    p.eax(0);
    p.call_vtable(V_RELEASE, &[M(locator)]);
    p.eax(0);
    p.finish()
}

fn com_bstr(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            (
                "oleaut32.dll",
                vec![
                    "SysAllocString".into(),
                    "SysAllocStringLen".into(),
                    "SysFreeString".into(),
                    "VariantInit".into(),
                ],
            ),
            ("kernel32.dll", vec!["lstrcmpW".into(), "lstrlenW".into()]),
        ],
    );
    const SYSALLOC: usize = 0;
    const SYSALLOCLEN: usize = 1;
    const SYSFREE: usize = 2;
    const VARIANTINIT: usize = 3;
    const CMP: usize = 4;
    const LEN: usize = 5;
    let hello = p.string("Hello");
    let bstr = p.scratch(16);
    let zeroed = p.scratch(16);
    let variant = p.scratch(32);

    // SysAllocString copies the text and terminates it.
    p.call(SYSALLOC, &[V(hello)]);
    p.nonzero();
    p.save(bstr);
    p.call(CMP, &[M(bstr), V(hello)]);
    p.eax(0);
    p.call(LEN, &[M(bstr)]);
    p.eax(5);

    // SysAllocStringLen with a null source gives a zero-filled string, so its
    // first unit is already the terminator.
    p.call(SYSALLOCLEN, &[V(0), V(4)]);
    p.nonzero();
    p.save(zeroed);
    p.call(LEN, &[M(zeroed)]);
    p.eax(0);

    p.call(SYSFREE, &[M(bstr)]);
    p.call(SYSFREE, &[M(zeroed)]);
    // A null BSTR is a documented no-op.
    p.call(SYSFREE, &[V(0)]);

    // VariantInit clears the variant to VT_EMPTY.
    p.poison(variant, 6);
    p.call(VARIANTINIT, &[V(variant)]);
    for index in 0..4 {
        p.dword(variant + index * 4, 0);
    }
    p.finish()
}

fn com_guid(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            ("ole32.dll", vec!["CoCreateGuid".into(), "StringFromCLSID".into()]),
            ("kernel32.dll", vec!["lstrcmpW".into()]),
        ],
    );
    const COCREATEGUID: usize = 0;
    const STRINGFROMCLSID: usize = 1;
    const CMP: usize = 2;
    let value = p.scratch(32);
    let text = p.scratch(16);
    let expected = p.string("{00000001-1111-4222-8333-000000000000}");

    // The first GUID of a run is deterministic and clearly synthetic.
    p.poison(value, 4);
    p.call(COCREATEGUID, &[V(value)]);
    p.eax(0);
    p.dword(value, 1);
    p.dword(value + 4, 0x4222_1111);
    p.dword(value + 8, 0x0000_3383);
    p.dword(value + 12, 0);

    // StringFromCLSID renders the braced upper-case form into allocated memory.
    p.call(STRINGFROMCLSID, &[V(value), V(text)]);
    p.eax(0);
    p.call(CMP, &[M(text), V(expected)]);
    p.eax(0);
    p.finish()
}

fn com_uuid(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            ("rpcrt4.dll", vec!["UuidCreate".into(), "UuidToStringA".into()]),
            ("kernel32.dll", vec!["lstrcmpA".into()]),
        ],
    );
    const UUIDCREATE: usize = 0;
    const UUIDTOSTRING: usize = 1;
    const CMP: usize = 2;
    let value = p.scratch(32);
    let text = p.scratch(16);
    let expected = p.ascii("00000001-1111-4222-8333-000000000000");

    p.poison(value, 4);
    p.call(UUIDCREATE, &[V(value)]);
    p.eax(0);
    p.dword(value, 1);
    p.dword(value + 4, 0x4222_1111);

    // The RPC string form is bare and lower case.
    p.call(UUIDTOSTRING, &[V(value), V(text)]);
    p.eax(0);
    p.call(CMP, &[M(text), V(expected)]);
    p.eax(0);
    p.finish()
}

fn com_shell(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        false,
        &[
            (
                "shell32.dll",
                vec![
                    "SHGetFolderPathA".into(),
                    "SHCreateDirectoryExA".into(),
                    "CommandLineToArgvA".into(),
                    "IsUserAnAdmin".into(),
                    "ShellExecuteA".into(),
                    "SHChangeNotify".into(),
                    "SHGetMalloc".into(),
                ],
            ),
            ("kernel32.dll", vec!["lstrcmpA".into()]),
        ],
    );
    const GETFOLDER: usize = 0;
    const CREATEDIR: usize = 1;
    const ARGV: usize = 2;
    const ISADMIN: usize = 3;
    const EXEC: usize = 4;
    const NOTIFY: usize = 5;
    const GETMALLOC: usize = 6;
    const CMP: usize = 7;

    let buffer = p.scratch(0x120);
    let count = p.scratch(16);
    let malloc = p.scratch(16);
    let block = p.scratch(16);
    let system = p.ascii(r"C:\Windows\System32");
    let windows = p.ascii(r"C:\Windows");
    let tree = p.ascii(r"C:\emumee\m7\deep");
    let command = p.ascii("p.exe alpha beta");
    let verb = p.ascii("open");
    let target = p.ascii(r"C:\payload.exe");

    // The persona is an ordinary interactive user, not elevated.
    p.call(ISADMIN, &[]);
    p.eax(0);

    // CSIDL_SYSTEM and CSIDL_WINDOWS come from the persona's configured
    // directories, so they are the same on every run.
    p.call(GETFOLDER, &[V(0), V(0x25), V(0), V(0), V(buffer)]);
    p.eax(0);
    p.call(CMP, &[V(buffer), V(system)]);
    p.eax(0);
    p.call(GETFOLDER, &[V(0), V(0x24), V(0), V(0), V(buffer)]);
    p.eax(0);
    p.call(CMP, &[V(buffer), V(windows)]);
    p.eax(0);
    // CSIDL_FLAG_CREATE must not change the answer.
    p.call(GETFOLDER, &[V(0), V(0x24 | 0x8000), V(0), V(0), V(buffer)]);
    p.eax(0);
    p.call(CMP, &[V(buffer), V(windows)]);
    p.eax(0);
    // An unknown folder id fails rather than inventing a path.
    p.call(GETFOLDER, &[V(0), V(0x99), V(0), V(0), V(buffer)]);
    p.eax(0x8000_4005);

    // A whole directory tree is created in the virtual filesystem.
    p.call(CREATEDIR, &[V(0), V(tree), V(0)]);
    p.eax(0);
    // Creating it again is not a failure for the Ex spelling.
    p.call(CREATEDIR, &[V(0), V(tree), V(0)]);
    p.eax(0);

    // Command-line splitting reports its argument count.
    p.set_dword(count, 0);
    p.call(ARGV, &[V(command), V(count)]);
    p.nonzero();
    p.dword(count, 3);

    // A launch request reports the success a caller checks for; no process runs.
    p.call(EXEC, &[V(0), V(verb), V(target), V(0), V(0), V(1)]);
    p.eax(42);
    p.call(NOTIFY, &[V(0), V(0), V(0), V(0)]);

    // SHGetMalloc hands back a real IMalloc over the guest heap.
    p.call(GETMALLOC, &[V(malloc)]);
    p.eax(0);
    p.call_vtable(V_MALLOC_ALLOC, &[M(malloc), V(64)]);
    p.nonzero();
    p.save(block);
    p.call_vtable(V_MALLOC_FREE, &[M(malloc), M(block)]);
    p.finish()
}

#[derive(Clone, Copy, Debug)]
pub enum M7SecurityFixture {
    /// SID construction, validation, comparison and copying.
    Sid,
    /// Token query, privilege lookup and the partial-success adjustment.
    Token,
    /// Account name and SID translation.
    Account,
    /// The extended user-name formats.
    UserName,
    /// Service creation, start, query, delete and the interactive dispatcher.
    Service,
    /// Audit category enumeration and the LSA package surface.
    Audit,
}

/// NT authority, as a SID_IDENTIFIER_AUTHORITY is laid out in memory.
const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

/// A SID's binary form, matching the model's layout.
fn sid(authority: u8, sub: &[u32]) -> Vec<u8> {
    let mut bytes = vec![1u8, sub.len() as u8];
    bytes.extend([0, 0, 0, 0, 0, authority]);
    for value in sub {
        bytes.extend(value.to_le_bytes());
    }
    bytes
}

/// The audit category GUID for `id`, matching the model's table.
fn audit_guid(id: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend((0x6997_9848u32 + id).to_le_bytes());
    bytes.extend(0x797Au16.to_le_bytes());
    bytes.extend(0x11D9u16.to_le_bytes());
    bytes.extend([0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30]);
    bytes
}

pub fn m7_security_probe(architecture: Architecture, kind: M7SecurityFixture) -> Vec<u8> {
    use M7SecurityFixture as K;
    match kind {
        K::Sid => security_sid(architecture),
        K::Token => security_token(architecture),
        K::Account => security_account(architecture),
        K::UserName => security_username(architecture),
        K::Service => security_service(architecture),
        K::Audit => security_audit(architecture),
    }
}

fn security_sid(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[(
            "advapi32.dll",
            vec![
                "AllocateAndInitializeSid".into(),
                "GetLengthSid".into(),
                "IsValidSid".into(),
                "EqualSid".into(),
                "CopySid".into(),
                "FreeSid".into(),
            ],
        )],
    );
    const ALLOCATE: usize = 0;
    const LENGTH: usize = 1;
    const VALID: usize = 2;
    const EQUAL: usize = 3;
    const COPY: usize = 4;
    const FREE: usize = 5;

    let authority = p.blob(&NT_AUTHORITY);
    // BUILTIN\Administrators is S-1-5-32-544.
    let administrators = p.blob(&sid(5, &[32, 544]));
    let everyone = p.blob(&sid(1, &[0]));
    // Revision 9 is not a SID revision this or any Windows accepts.
    let bogus = p.blob(&[9, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0]);
    let allocated = p.scratch(16);
    let destination = p.scratch(64);

    // AllocateAndInitializeSid takes eight sub-authority slots regardless of
    // how many the count names.
    p.call(
        ALLOCATE,
        &[
            V(authority),
            V(2),
            V(32),
            V(544),
            V(0),
            V(0),
            V(0),
            V(0),
            V(0),
            V(0),
            V(allocated),
        ],
    );
    p.eax(1);
    // Two sub-authorities: 8 header bytes plus two four-byte values.
    p.call(LENGTH, &[M(allocated)]);
    p.eax(16);
    p.call(VALID, &[M(allocated)]);
    p.eax(1);
    // The bytes it built are exactly the well-known Administrators SID.
    p.call(EQUAL, &[M(allocated), V(administrators)]);
    p.eax(1);
    p.call(EQUAL, &[M(allocated), V(everyone)]);
    p.eax(0);
    p.call(VALID, &[V(bogus)]);
    p.eax(0);

    // A copy into a large enough buffer compares equal; a short one is refused.
    p.call(COPY, &[V(64), V(destination), M(allocated)]);
    p.eax(1);
    p.call(EQUAL, &[V(destination), V(administrators)]);
    p.eax(1);
    p.call(COPY, &[V(8), V(destination), M(allocated)]);
    p.eax(0);

    // FreeSid answers NULL.
    p.call(FREE, &[M(allocated)]);
    p.eax(0);
    p.finish()
}

fn security_token(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            (
                "advapi32.dll",
                vec![
                    "OpenProcessToken".into(),
                    "LookupPrivilegeValueW".into(),
                    "AdjustTokenPrivileges".into(),
                    "GetTokenInformation".into(),
                    "CheckTokenMembership".into(),
                ],
            ),
            ("kernel32.dll", vec!["GetLastError".into()]),
        ],
    );
    const OPENTOKEN: usize = 0;
    const LOOKUPVALUE: usize = 1;
    const ADJUST: usize = 2;
    const TOKENINFO: usize = 3;
    const MEMBERSHIP: usize = 4;
    const LASTERROR: usize = 5;

    let debug_name = p.string("SeDebugPrivilege");
    let notify_name = p.string("SeChangeNotifyPrivilege");
    let administrators = p.blob(&sid(5, &[32, 544]));
    let everyone = p.blob(&sid(1, &[0]));
    let token = p.scratch(16);
    let luid = p.scratch(16);
    let privileges = p.scratch(32);
    let buffer = p.scratch(64);
    let returned = p.scratch(16);
    let member = p.scratch(16);

    p.call(OPENTOKEN, &[V(u64::MAX), V(0x8 | 0x20), V(token)]);
    p.eax(1);

    // SeDebugPrivilege has the well-known LUID 20.
    p.poison(luid, 2);
    p.call(LOOKUPVALUE, &[V(0), V(debug_name), V(luid)]);
    p.eax(1);
    p.dword(luid, 20);
    p.dword(luid + 4, 0);

    // The persona's token does not hold SeDebugPrivilege, so enabling it is the
    // documented partial success: TRUE with ERROR_NOT_ALL_ASSIGNED.
    p.set_dword(privileges, 1);
    p.set_dword(privileges + 4, 20);
    p.set_dword(privileges + 8, 0);
    p.set_dword(privileges + 12, 2);
    p.call(ADJUST, &[M(token), V(0), V(privileges), V(0), V(0), V(0)]);
    p.eax(1);
    p.call(LASTERROR, &[]);
    p.eax(1300);

    // A privilege the token does hold is enabled cleanly.
    p.call(LOOKUPVALUE, &[V(0), V(notify_name), V(luid)]);
    p.eax(1);
    p.dword(luid, 23);
    p.set_dword(privileges, 1);
    p.set_dword(privileges + 4, 23);
    p.set_dword(privileges + 8, 0);
    p.set_dword(privileges + 12, 2);
    p.call(ADJUST, &[M(token), V(0), V(privileges), V(0), V(0), V(0)]);
    p.eax(1);
    p.call(LASTERROR, &[]);
    p.eax(0);

    // TokenElevation reports an ordinary, non-elevated user.
    p.poison(buffer, 2);
    p.set_dword(returned, 0);
    p.call(TOKENINFO, &[M(token), V(20), V(buffer), V(4), V(returned)]);
    p.eax(1);
    p.dword(buffer, 0);
    p.dword(returned, 4);

    // A buffer that cannot hold the answer is refused and reports the size.
    p.call(TOKENINFO, &[M(token), V(1), V(buffer), V(1), V(returned)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(122);

    // The user is not an administrator but is a member of Everyone.
    p.set_dword(member, 0x5a);
    p.call(MEMBERSHIP, &[M(token), V(administrators), V(member)]);
    p.eax(1);
    p.dword(member, 0);
    p.call(MEMBERSHIP, &[M(token), V(everyone), V(member)]);
    p.eax(1);
    p.dword(member, 1);
    p.finish()
}

fn security_account(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            (
                "advapi32.dll",
                vec!["LookupAccountNameW".into(), "LookupAccountSidW".into()],
            ),
            ("kernel32.dll", vec!["GetLastError".into()]),
        ],
    );
    const BYNAME: usize = 0;
    const BYSID: usize = 1;
    const LASTERROR: usize = 2;

    let everyone_name = p.string("Everyone");
    let everyone = p.blob(&sid(1, &[0]));
    let unknown = p.string("NoSuchAccount");
    let sid_buffer = p.scratch(64);
    let sid_len = p.scratch(16);
    let domain = p.scratch(0x80);
    let domain_len = p.scratch(16);
    let use_kind = p.scratch(16);
    let name = p.scratch(0x80);
    let name_len = p.scratch(16);

    // A null account name resolves the persona's own user: five sub-authorities
    // make a 28-byte SID, reported as SidTypeUser.
    p.set_dword(sid_len, 64);
    p.set_dword(domain_len, 64);
    p.call(
        BYNAME,
        &[V(0), V(0), V(sid_buffer), V(sid_len), V(domain), V(domain_len), V(use_kind)],
    );
    p.eax(1);
    p.dword(sid_len, 28);
    p.dword(use_kind, 1);

    // The SID just produced translates back to the same account.
    p.set_dword(name_len, 64);
    p.set_dword(domain_len, 64);
    p.call(
        BYSID,
        &[V(0), V(sid_buffer), V(name), V(name_len), V(domain), V(domain_len), V(use_kind)],
    );
    p.eax(1);
    p.dword(use_kind, 1);

    // A well-known group is a group, not a user.
    p.set_dword(sid_len, 64);
    p.set_dword(domain_len, 64);
    p.call(
        BYNAME,
        &[
            V(0),
            V(everyone_name),
            V(sid_buffer),
            V(sid_len),
            V(domain),
            V(domain_len),
            V(use_kind),
        ],
    );
    p.eax(1);
    p.dword(sid_len, 12);
    p.dword(use_kind, 4);
    // The in/out counts were consumed by the calls above and must be reset.
    p.set_dword(name_len, 64);
    p.set_dword(domain_len, 64);
    p.call(BYSID, &[V(0), V(everyone), V(name), V(name_len), V(domain), V(domain_len), V(use_kind)]);
    p.eax(1);
    p.dword(use_kind, 4);

    // An account that does not exist is not invented.
    p.set_dword(sid_len, 64);
    p.set_dword(domain_len, 64);
    p.call(
        BYNAME,
        &[V(0), V(unknown), V(sid_buffer), V(sid_len), V(domain), V(domain_len), V(use_kind)],
    );
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(1332);
    p.finish()
}

fn security_username(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            ("secur32.dll", vec!["GetUserNameExW".into()]),
            ("kernel32.dll", vec!["lstrcmpW".into(), "GetLastError".into()]),
        ],
    );
    const USERNAMEEX: usize = 0;
    const CMP: usize = 1;
    const LASTERROR: usize = 2;

    let buffer = p.scratch(0x100);
    let size = p.scratch(16);
    // The fixture persona is DESKTOP-7F4M2Q9\Alex.
    let sam = p.string(r"DESKTOP-7F4M2Q9\Alex");
    let display = p.string("Alex");

    // NameSamCompatible is the machine-qualified form.
    p.set_dword(size, 128);
    p.call(USERNAMEEX, &[V(2), V(buffer), V(size)]);
    p.eax(1);
    p.call(CMP, &[V(buffer), V(sam)]);
    p.eax(0);

    // NameDisplay is the bare user name.
    p.set_dword(size, 128);
    p.call(USERNAMEEX, &[V(3), V(buffer), V(size)]);
    p.eax(1);
    p.call(CMP, &[V(buffer), V(display)]);
    p.eax(0);

    // An unmodeled format is refused rather than answered.
    p.set_dword(size, 128);
    p.call(USERNAMEEX, &[V(99), V(buffer), V(size)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(87);
    p.finish()
}

fn security_service(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            (
                "advapi32.dll",
                vec![
                    "OpenSCManagerW".into(),
                    "CreateServiceW".into(),
                    "OpenServiceW".into(),
                    "QueryServiceStatus".into(),
                    "StartServiceW".into(),
                    "QueryServiceConfigW".into(),
                    "DeleteService".into(),
                    "CloseServiceHandle".into(),
                    "StartServiceCtrlDispatcherW".into(),
                ],
            ),
            ("kernel32.dll", vec!["GetLastError".into()]),
        ],
    );
    const OPENSCM: usize = 0;
    const CREATE: usize = 1;
    const OPEN: usize = 2;
    const QUERYSTATUS: usize = 3;
    const START: usize = 4;
    const QUERYCONFIG: usize = 5;
    const DELETE: usize = 6;
    const CLOSE: usize = 7;
    const DISPATCHER: usize = 8;
    const LASTERROR: usize = 9;

    let name = p.string("EmumeeM7Svc");
    let display = p.string("Emumee M7 Service");
    let binary = p.string(r"C:\emumee\svc.exe");
    let scm = p.scratch(16);
    let service = p.scratch(16);
    let status = p.scratch(64);
    let config = p.scratch(0x200);
    let needed = p.scratch(16);
    let table = p.scratch(32);

    p.call(OPENSCM, &[V(0), V(0), V(0xF003F)]);
    p.nonzero();
    p.save(scm);

    // SERVICE_WIN32_OWN_PROCESS started automatically at boot: the classic
    // persistence shape, recorded in full.
    p.call(
        CREATE,
        &[
            M(scm),
            V(name),
            V(display),
            V(0xF01FF),
            V(0x10),
            V(2),
            V(1),
            V(binary),
            V(0),
            V(0),
            V(0),
            V(0),
            V(0),
        ],
    );
    p.nonzero();
    p.save(service);

    // A freshly created service is stopped.
    p.poison(status, 7);
    p.call(QUERYSTATUS, &[M(service), V(status)]);
    p.eax(1);
    p.dword(status, 0x10);
    p.dword(status + 4, 1);

    // Starting it marks the record running; nothing is executed.
    p.call(START, &[M(service), V(0), V(0)]);
    p.eax(1);
    p.call(QUERYSTATUS, &[M(service), V(status)]);
    p.eax(1);
    p.dword(status + 4, 4);

    // The stored configuration reads back.
    p.set_dword(needed, 0);
    p.call(QUERYCONFIG, &[M(service), V(config), V(0x200), V(needed)]);
    p.eax(1);
    p.dword(config, 0x10);
    p.dword(config + 4, 2);

    // A second service of the same name already exists.
    p.call(
        CREATE,
        &[
            M(scm),
            V(name),
            V(display),
            V(0xF01FF),
            V(0x10),
            V(2),
            V(1),
            V(binary),
            V(0),
            V(0),
            V(0),
            V(0),
            V(0),
        ],
    );
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(1073);

    // After deletion the name no longer resolves.
    p.call(DELETE, &[M(service)]);
    p.eax(1);
    p.call(OPEN, &[M(scm), V(name), V(0xF01FF)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(1060);

    // Run interactively there is no service controller to connect to.
    p.set_dword(table, 0);
    p.call(DISPATCHER, &[V(table)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(1063);

    p.call(CLOSE, &[M(service)]);
    p.eax(1);
    p.call(CLOSE, &[M(scm)]);
    p.eax(1);
    p.finish()
}

fn security_audit(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            (
                "advapi32.dll",
                vec![
                    "AuditEnumerateCategories".into(),
                    "AuditLookupCategoryIdFromCategoryGuid".into(),
                    "AuditQuerySystemPolicy".into(),
                    "AuditFree".into(),
                ],
            ),
            (
                "secur32.dll",
                vec![
                    "LsaConnectUntrusted".into(),
                    "LsaCallAuthenticationPackage".into(),
                    "LsaDeregisterLogonProcess".into(),
                ],
            ),
        ],
    );
    const ENUMCATS: usize = 0;
    const IDFROMGUID: usize = 1;
    const QUERYPOLICY: usize = 2;
    const AUDITFREE: usize = 3;
    const LSACONNECT: usize = 4;
    const LSACALL: usize = 5;
    const LSADEREGISTER: usize = 6;

    let system_guid = p.blob(&audit_guid(0));
    let logon_guid = p.blob(&audit_guid(1));
    let categories = p.scratch(16);
    let count = p.scratch(16);
    let id = p.scratch(16);
    let policy = p.scratch(16);
    let lsa = p.scratch(16);
    let return_buffer = p.scratch(16);
    let return_length = p.scratch(16);
    let protocol_status = p.scratch(16);

    // Nine well-known audit categories.
    p.set_dword(count, 0);
    p.call(ENUMCATS, &[V(categories), V(count)]);
    p.eax(1);
    p.dword(count, 9);
    p.call(AUDITFREE, &[M(categories)]);

    // Each category GUID maps back to its own id.
    p.set_dword(id, 0x5a);
    p.call(IDFROMGUID, &[V(system_guid), V(id)]);
    p.eax(1);
    p.dword(id, 0);
    p.call(IDFROMGUID, &[V(logon_guid), V(id)]);
    p.eax(1);
    p.dword(id, 1);

    // The default policy audits nothing.
    p.call(QUERYPOLICY, &[V(system_guid), V(1), V(policy)]);
    p.eax(1);
    p.call(AUDITFREE, &[M(policy)]);

    // The credential-enumeration path is observed and answers nothing.
    p.call(LSACONNECT, &[V(lsa)]);
    p.eax(0);
    p.set_dword(return_length, 0x5a);
    p.call(
        LSACALL,
        &[
            M(lsa),
            V(0),
            V(0),
            V(0),
            V(return_buffer),
            V(return_length),
            V(protocol_status),
        ],
    );
    p.eax(0);
    p.dword(return_length, 0);
    p.dword(protocol_status, 0xC000_00BB);
    p.call(LSADEREGISTER, &[M(lsa)]);
    p.eax(0);
    p.finish()
}

#[derive(Clone, Copy, Debug)]
pub enum M7SocketFixture {
    /// Startup bookkeeping, byte order and address text.
    Core,
    /// Socket lifecycle, the recorded outbound attempts and inbound denial.
    Transfer,
}

pub fn m7_socket_probe(architecture: Architecture, kind: M7SocketFixture) -> Vec<u8> {
    match kind {
        M7SocketFixture::Core => socket_core(architecture),
        M7SocketFixture::Transfer => socket_transfer(architecture),
    }
}

fn socket_core(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        false,
        &[(
            "ws2_32.dll",
            vec![
                "WSAStartup".into(),
                "WSACleanup".into(),
                "WSAGetLastError".into(),
                "htons".into(),
                "htonl".into(),
                "inet_addr".into(),
                "inet_pton".into(),
                "inet_ntop".into(),
                "gethostname".into(),
                "select".into(),
                "socket".into(),
            ],
        )],
    );
    const STARTUP: usize = 0;
    const CLEANUP: usize = 1;
    const LASTERROR: usize = 2;
    const HTONS: usize = 3;
    const HTONL: usize = 4;
    const INETADDR: usize = 5;
    const INETPTON: usize = 6;
    const INETNTOP: usize = 7;
    const GETHOSTNAME: usize = 8;
    const SELECT: usize = 9;
    const SOCKET: usize = 10;

    let wsadata = p.scratch(0x200);
    let text = p.ascii("10.0.2.15");
    let dotted = p.ascii("192.168.1.200");
    let packed = p.scratch(16);
    let out = p.scratch(64);
    let host = p.scratch(64);

    // Byte-order helpers work before the stack is initialized.
    p.call(HTONS, &[V(0x1234)]);
    p.eax(0x3412);
    p.call(HTONL, &[V(0x1122_3344)]);
    p.eax(0x4433_2211);

    // Nothing else may run before WSAStartup.
    p.call(SOCKET, &[V(2), V(1), V(6)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(10093);

    // WSAStartup negotiates 2.2 and fills the version words.
    p.call(STARTUP, &[V(0x0202), V(wsadata)]);
    p.eax(0);
    p.dword(wsadata, 0x0202_0202);

    // inet_addr answers network byte order.
    p.call(INETADDR, &[V(text)]);
    p.eax(0x0F02_000A);

    // inet_pton parses and inet_ntop renders the same address.
    p.poison(packed, 1);
    p.call(INETPTON, &[V(2), V(dotted), V(packed)]);
    p.eax(1);
    p.dword(packed, 0xC801_A8C0);
    p.poison(out, 5);
    p.call(INETNTOP, &[V(2), V(packed), V(out), V(32)]);
    p.rax(out);
    p.check(out, b"192.168.1.200\0", POISON.to_le_bytes()[0]);

    // The host name is the persona's, which begins "DESK".
    p.call(GETHOSTNAME, &[V(host), V(64)]);
    p.eax(0);
    p.dword(host, 0x4B53_4544);

    // No socket is ever ready, so select reports its timeout.
    p.call(SELECT, &[V(0), V(0), V(0), V(0), V(0)]);
    p.eax(0);

    p.call(CLEANUP, &[]);
    p.eax(0);
    // After the last cleanup the stack is uninitialized again.
    p.call(CLEANUP, &[]);
    p.eax(10093);
    p.finish()
}

fn socket_transfer(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        false,
        &[(
            "ws2_32.dll",
            vec![
                "WSAStartup".into(),
                "WSAGetLastError".into(),
                "socket".into(),
                "closesocket".into(),
                "bind".into(),
                "listen".into(),
                "connect".into(),
                "send".into(),
                "getsockopt".into(),
                "ioctlsocket".into(),
                "gethostbyname".into(),
            ],
        )],
    );
    const STARTUP: usize = 0;
    const LASTERROR: usize = 1;
    const SOCKET: usize = 2;
    const CLOSESOCKET: usize = 3;
    const BIND: usize = 4;
    const LISTEN: usize = 5;
    const CONNECT: usize = 6;
    const SEND: usize = 7;
    const GETSOCKOPT: usize = 8;
    const IOCTLSOCKET: usize = 9;
    const GETHOSTBYNAME: usize = 10;

    let wsadata = p.scratch(0x200);
    let socket_handle = p.scratch(16);
    let local = p.scratch(16);
    let remote = p.scratch(16);
    let payload = p.ascii("GET / HTTP/1.0");
    let option = p.scratch(16);
    let option_len = p.scratch(16);
    let mode = p.scratch(16);
    let localhost = p.ascii("localhost");
    let missing = p.ascii("no-such-host.invalid");

    p.call(STARTUP, &[V(0x0202), V(wsadata)]);
    p.eax(0);

    // An address family this profile does not carry is refused.
    p.call(SOCKET, &[V(23), V(1), V(6)]);
    p.eax(0xFFFF_FFFF);
    p.call(LASTERROR, &[]);
    p.eax(10047);

    // A TCP socket opens.
    p.call(SOCKET, &[V(2), V(1), V(6)]);
    p.opened();
    p.save(socket_handle);

    // SO_TYPE reads back the socket's own type.
    p.set_dword(option_len, 4);
    p.poison(option, 1);
    p.call(
        GETSOCKOPT,
        &[M(socket_handle), V(0xFFFF), V(0x1008), V(option), V(option_len)],
    );
    p.eax(0);
    p.dword(option, 1);
    p.dword(option_len, 4);

    // Non-blocking mode is accepted.
    p.set_dword(mode, 1);
    p.call(IOCTLSOCKET, &[M(socket_handle), V(0x8004_667E), V(mode)]);
    p.eax(0);

    // Binding a local address needs no network: sockaddr_in for 0.0.0.0:8080.
    p.set_dword(local, 0x901F_0002);
    p.set_dword(local + 4, 0);
    p.set_dword(local + 8, 0);
    p.set_dword(local + 12, 0);
    p.call(BIND, &[M(socket_handle), V(local), V(16)]);
    p.eax(0);

    // Inbound networking stays refused.
    p.call(LISTEN, &[M(socket_handle), V(5)]);
    p.eax(0xFFFF_FFFF);
    p.call(LASTERROR, &[]);
    p.eax(10045);

    // The connect destination is recorded, then the network reports unreachable.
    p.set_dword(remote, 0x901F_0002);
    p.set_dword(remote + 4, 0x0F02_000A);
    p.set_dword(remote + 8, 0);
    p.set_dword(remote + 12, 0);
    p.call(CONNECT, &[M(socket_handle), V(remote), V(16)]);
    p.eax(0xFFFF_FFFF);
    p.call(LASTERROR, &[]);
    p.eax(10051);

    // The payload is captured even though the socket is not connected.
    p.call(SEND, &[M(socket_handle), V(payload), V(14), V(0)]);
    p.eax(0xFFFF_FFFF);
    p.call(LASTERROR, &[]);
    p.eax(10057);

    // Loopback resolves; a name this profile cannot answer is not invented.
    p.call(GETHOSTBYNAME, &[V(localhost)]);
    p.nonzero();
    p.call(GETHOSTBYNAME, &[V(missing)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(11001);

    p.call(CLOSESOCKET, &[M(socket_handle)]);
    p.eax(0);
    // The handle is gone, so closing it again is not a socket.
    p.call(CLOSESOCKET, &[M(socket_handle)]);
    p.eax(0xFFFF_FFFF);
    p.call(LASTERROR, &[]);
    p.eax(10038);
    p.finish()
}

/// The default adapter's identity, as the controls expect to read it back.
/// Addresses are the `IPAddr` words a structure field carries: the four octets
/// in network order, read as a little-endian word.
const HOST_WORD: u32 = 0x0F02_000A; // 10.0.2.15
const MASK_WORD: u32 = 0x00FF_FFFF; // 255.255.255.0
const GATEWAY_WORD: u32 = 0x0202_000A; // 10.0.2.2
const NETWORK_WORD: u32 = 0x0002_000A; // 10.0.2.0
const BROADCAST_WORD: u32 = 0xFF02_000A; // 10.0.2.255
const DNS_WORD: u32 = 0x0302_000A; // 10.0.2.3
const LOOPBACK_WORD: u32 = 0x0100_007F; // 127.0.0.1
/// 00-15-5D-2E-4A-71, as the two words a six-octet field occupies.
const MAC_LOW: u32 = 0x2E5D_1500;
const MAC_HIGH: u32 = 0x0000_714A;
const IF_INDEX: u32 = 12;
const MTU: u32 = 1500;
/// MIB_IF_TYPE_ETHERNET.
const ETHERNET: u32 = 6;
const HOST_NAME: &str = "DESKTOP-7F4M2Q9";
const WORKGROUP: &str = "WORKGROUP";

fn width(p: &Probe) -> u64 {
    if p.wide { 8 } else { 4 }
}

/// Store a pointer-width value, so a control can build a structure whose
/// fields are pointers in either architecture.
fn set_pointer(p: &mut Probe, address: u64, value: u64) {
    if p.wide {
        p.set_qword(address, value);
    } else {
        p.set_dword(address, value as u32);
    }
}

#[derive(Clone, Copy, Debug)]
pub enum M7NetworkFixture {
    /// `GetAdaptersInfo`, `GetNetworkParams` and the prefix-to-mask helper.
    Adapter,
    /// `GetAdaptersAddresses`, including the linked unicast and DNS nodes.
    Addresses,
    /// The MIB interface, address, route, ARP and TCP tables.
    Tables,
    /// ICMP echo: the local reply, the recorded timeout and handle lifetime.
    Icmp,
    /// `DnsQuery_W` answers, refusals and the record list it publishes.
    Dns,
    /// Join and workstation information, and the account-creation attempt.
    Workstation,
    /// The network redirector: share mapping, enumeration and connections.
    Redirector,
    /// `InternetCrackUrl` in both documented modes.
    CrackUrl,
    /// WinINet handle options and the connected-state query.
    Options,
    /// WinHTTP URL cracking, proxy configuration, options and headers.
    WinHttp,
}

pub fn m7_network_probe(architecture: Architecture, kind: M7NetworkFixture) -> Vec<u8> {
    match kind {
        M7NetworkFixture::Adapter => network_adapter(architecture),
        M7NetworkFixture::Addresses => network_addresses(architecture),
        M7NetworkFixture::Tables => network_tables(architecture),
        M7NetworkFixture::Icmp => network_icmp(architecture),
        M7NetworkFixture::Dns => network_dns(architecture),
        M7NetworkFixture::Workstation => network_workstation(architecture),
        M7NetworkFixture::Redirector => network_redirector(architecture),
        M7NetworkFixture::CrackUrl => network_crack_url(architecture),
        M7NetworkFixture::Options => network_options(architecture),
        M7NetworkFixture::WinHttp => network_winhttp(architecture),
    }
}

/// `GetAdaptersInfo` and `GetNetworkParams`: the adapter identity, its address
/// text and the DNS server chain, each read back at the offset the real
/// structure puts it.
fn network_adapter(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        false,
        &[(
            "iphlpapi.dll",
            vec![
                "ConvertLengthToIpv4Mask".into(),
                "GetAdaptersInfo".into(),
                "GetNetworkParams".into(),
            ],
        )],
    );
    const MASK: usize = 0;
    const INFO: usize = 1;
    const PARAMS: usize = 2;

    let w = width(&p);
    // IP_ADAPTER_INFO and FIXED_INFO sizes, and the offsets this control reads.
    let (info_size, fixed_size) = if p.wide { (704u32, 600u32) } else { (648, 584) };
    let strings = if p.wide { 48 } else { 40 };
    let address_list = if p.wide { 440 } else { 428 };
    let gateway_list = address_list + strings;
    let dns_list = 264 + w;

    let out = p.scratch(16);
    let size = p.scratch(16);
    let info = p.scratch(768);
    let fixed = p.scratch(640);

    // A prefix length becomes a mask in network order; past 32 is refused.
    p.poison(out, 1);
    p.call(MASK, &[V(24), V(out)]);
    p.eax(0);
    p.dword(out, MASK_WORD);
    p.call(MASK, &[V(33), V(out)]);
    p.eax(87);
    p.dword(out, 0xFFFF_FFFF);

    // A null buffer learns the exact size one adapter needs.
    p.set_dword(size, 0);
    p.call(INFO, &[V(0), V(size)]);
    p.eax(111);
    p.dword(size, info_size);

    // The adapter itself: index, type, physical address and the address,
    // mask and gateway as the fixed-width text the structure carries.
    p.set_dword(size, info_size);
    p.call(INFO, &[V(info), V(size)]);
    p.eax(0);
    p.dword(info + w + 408, IF_INDEX);
    p.dword(info + w + 412, ETHERNET);
    p.dword(info + w + 396, 6);
    p.dword(info + w + 400, MAC_LOW);
    p.dword(info + w + 404, MAC_HIGH);
    p.check(info + address_list + w, b"10.0.2.15\0", 0);
    p.check(info + address_list + w + 16, b"255.255.255.0\0", 0);
    p.check(info + gateway_list + w, b"10.0.2.2\0", 0);
    // The lease times are deliberately zero: no clock may leak into a table.
    p.qword(info + if p.wide { 688 } else { 632 }, 0);

    // GetNetworkParams reports the host name and the DNS server chain.
    p.set_dword(size, 0);
    p.call(PARAMS, &[V(0), V(size)]);
    p.eax(111);
    p.dword(size, fixed_size);
    p.set_dword(size, fixed_size);
    p.call(PARAMS, &[V(fixed), V(size)]);
    p.eax(0);
    p.check(fixed, b"DESKTOP-7F4M2Q9\0", 0);
    // A workgroup persona has no DNS suffix, and one DNS server with no next.
    p.dword(fixed + 132, 0);
    p.check(fixed + dns_list + w, b"10.0.2.3\0", 0);
    p.dword(fixed + dns_list, 0);
    // A hybrid NetBIOS node, with routing off and DNS enabled.
    p.dword(fixed + dns_list + strings, 8);
    let routing = if p.wide { 584 } else { 572 };
    p.dword(fixed + routing, 0);
    p.dword(fixed + routing + 8, 1);
    p.finish()
}

/// `GetAdaptersAddresses`: the modern linked graph. Every interior pointer is
/// asserted at the exact address the caller's own buffer puts it, so a wrong
/// layout cannot pass.
fn network_addresses(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        false,
        &[("iphlpapi.dll", vec!["GetAdaptersAddresses".into()])],
    );
    const ADDRESSES: usize = 0;

    let w = width(&p);
    // The structure sizes, and the offsets this control reads.
    let head_size = if p.wide { 448u64 } else { 376 };
    let unicast_size = if p.wide { 64u64 } else { 48 };
    let node_size = if p.wide { 32u64 } else { 24 };
    let node_address = if p.wide { 16u64 } else { 12 };
    let (first_unicast, first_dns, physical, physical_length) =
        if p.wide { (24u64, 48u64, 80u64, 88u64) } else { (16, 28, 44, 52) };
    let (mtu_at, if_type, oper_status) = if p.wide { (96u64, 100u64, 104u64) } else { (60, 64, 68) };
    let unicast_address = if p.wide { 16u64 } else { 12 };

    let size = p.scratch(16);
    let buffer = p.scratch(1024);

    // An IPv6-only enumeration has nothing to report, and an unmodeled flag
    // is refused rather than answered with a partial graph.
    p.set_dword(size, 0);
    p.call(ADDRESSES, &[V(23), V(0), V(0), V(0), V(size)]);
    p.eax(232);
    p.call(ADDRESSES, &[V(2), V(0x1000), V(0), V(0), V(size)]);
    p.eax(50);
    // The reserved argument must be zero.
    p.call(ADDRESSES, &[V(2), V(0), V(1), V(0), V(size)]);
    p.eax(87);

    // The size one adapter needs, then the graph itself.
    p.call(ADDRESSES, &[V(2), V(0), V(0), V(0), V(size)]);
    p.eax(111);
    p.dword_not(size, 0);
    p.set_dword(size, 1024);
    p.call(ADDRESSES, &[V(2), V(0), V(0), V(buffer), V(size)]);
    p.eax(0);
    p.dword(buffer, head_size as u32);
    p.dword(buffer + 4, IF_INDEX);
    // One adapter, so there is no next.
    p.dword(buffer + 8, 0);
    p.dword(buffer + physical, MAC_LOW);
    p.dword(buffer + physical_length, 6);
    p.dword(buffer + mtu_at, MTU);
    p.dword(buffer + if_type, ETHERNET);
    p.dword(buffer + oper_status, 1);
    // The unicast node follows the adapter, and the DNS node follows it.
    p.dword(buffer + first_unicast, (buffer + head_size) as u32);
    p.dword(buffer + first_dns, (buffer + head_size + unicast_size) as u32);
    let unicast = buffer + head_size;
    let server = unicast + unicast_size;
    p.dword(unicast, unicast_size as u32);
    p.dword(unicast + 8, 0);
    // The prefix origin is DHCP, and the prefix length sits past the
    // lifetimes; the address itself is a real sockaddr_in to read through.
    p.dword(unicast + unicast_address + 2 * w, 3);
    p.dword(unicast + unicast_address + 2 * w + 24, 24);
    p.indirect_dword(unicast + unicast_address, 4, HOST_WORD);
    p.dword(server, node_size as u32);
    p.dword(server + 8, 0);
    p.indirect_dword(server + node_address, 4, DNS_WORD);
    p.finish()
}

/// The MIB tables: one interface, one address, three routes, one ARP entry and
/// an empty TCP table.
fn network_tables(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        false,
        &[(
            "iphlpapi.dll",
            vec![
                "GetIfTable".into(),
                "GetIpAddrTable".into(),
                "GetIpForwardTable".into(),
                "GetIpNetTable".into(),
                "GetExtendedTcpTable".into(),
            ],
        )],
    );
    const IF_TABLE: usize = 0;
    const ADDR_TABLE: usize = 1;
    const FORWARD_TABLE: usize = 2;
    const NET_TABLE: usize = 3;
    const TCP_TABLE: usize = 4;

    let size = p.scratch(16);
    let table = p.scratch(1024);

    // The interface table: a short buffer learns the size, then the row.
    p.set_dword(size, 0);
    p.call(IF_TABLE, &[V(0), V(size), V(0)]);
    p.eax(122);
    p.dword(size, 864);
    p.set_dword(size, 1024);
    p.call(IF_TABLE, &[V(table), V(size), V(0)]);
    p.eax(0);
    p.dword(table, 1);
    p.dword(table + 4 + 512, IF_INDEX);
    p.dword(table + 4 + 516, ETHERNET);
    p.dword(table + 4 + 520, MTU);
    p.dword(table + 4 + 528, 6);
    p.dword(table + 4 + 532, MAC_LOW);
    // Administratively up and operationally connected, with no traffic yet.
    p.dword(table + 4 + 540, 1);
    p.dword(table + 4 + 544, 5);
    p.dword(table + 4 + 552, 0);

    // The address table: the adapter's own address and mask.
    p.set_dword(size, 1024);
    p.call(ADDR_TABLE, &[V(table), V(size), V(0)]);
    p.eax(0);
    p.dword(table, 1);
    p.dword(table + 4, HOST_WORD);
    p.dword(table + 8, IF_INDEX);
    p.dword(table + 12, MASK_WORD);

    // The routing table, sorted: the default route through the gateway, the
    // on-link subnet and the host route for the adapter's own address.
    p.set_dword(size, 1024);
    p.call(FORWARD_TABLE, &[V(table), V(size), V(1)]);
    p.eax(0);
    p.dword(table, 3);
    p.dword(table + 4, 0);
    p.dword(table + 4 + 12, GATEWAY_WORD);
    p.dword(table + 4 + 20, 4);
    p.dword(table + 4 + 56, NETWORK_WORD);
    p.dword(table + 4 + 56 + 4, MASK_WORD);
    p.dword(table + 4 + 56 + 20, 3);
    p.dword(table + 4 + 112, HOST_WORD);

    // The ARP table: the subnet broadcast, which needs no invented neighbour.
    p.set_dword(size, 1024);
    p.call(NET_TABLE, &[V(table), V(size), V(0)]);
    p.eax(0);
    p.dword(table, 1);
    p.dword(table + 4, IF_INDEX);
    p.dword(table + 4 + 16, BROADCAST_WORD);
    p.dword(table + 4 + 20, 4);

    // The TCP table is genuinely empty, and an unmodeled family is refused.
    p.set_dword(size, 1024);
    p.call(TCP_TABLE, &[V(table), V(size), V(0), V(2), V(5), V(0)]);
    p.eax(0);
    p.dword(table, 0);
    p.dword(size, 4);
    p.call(TCP_TABLE, &[V(table), V(size), V(0), V(23), V(5), V(0)]);
    p.eax(50);
    p.finish()
}

/// ICMP echo: loopback replies for real, an address this profile cannot reach
/// times out, and the handle lifetime is enforced.
fn network_icmp(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        false,
        &[
            (
                "iphlpapi.dll",
                vec![
                    "IcmpCreateFile".into(),
                    "IcmpSendEcho".into(),
                    "IcmpCloseHandle".into(),
                ],
            ),
            ("kernel32.dll", vec!["GetLastError".into()]),
        ],
    );
    const CREATE: usize = 0;
    const ECHO: usize = 1;
    const CLOSE: usize = 2;
    const LASTERROR: usize = 3;

    let header = if p.wide { 40u64 } else { 28 };
    let handle = p.scratch(16);
    let request = p.ascii("EMUMEE-PING");
    let reply = p.scratch(128);

    p.call(CREATE, &[]);
    p.opened();
    p.save(handle);

    // Loopback answers locally: status IP_SUCCESS, the payload echoed back,
    // the reply data pointer inside the caller's buffer and a TTL of 128.
    p.poison(reply, 16);
    p.call(
        ECHO,
        &[
            M(handle),
            V(u64::from(LOOPBACK_WORD)),
            V(request),
            V(11),
            V(0),
            V(reply),
            V(128),
            V(1000),
        ],
    );
    p.eax(1);
    p.dword(reply, LOOPBACK_WORD);
    p.dword(reply + 4, 0);
    p.dword(reply + 8, 0);
    p.dword(reply + 12, 11);
    p.dword(reply + 16, (reply + header) as u32);
    p.dword(reply + if p.wide { 24 } else { 20 }, 128);
    p.check(reply + header, b"EMUMEE-PING", POISON.to_le_bytes()[0]);

    // A peer this profile has no network for times out, and the attempt is
    // recorded rather than answered.
    p.call(
        ECHO,
        &[
            M(handle),
            V(0x6302_000A),
            V(request),
            V(11),
            V(0),
            V(reply),
            V(128),
            V(500),
        ],
    );
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(11010);

    // A reply buffer too small for the header is refused outright.
    p.call(
        ECHO,
        &[
            M(handle),
            V(u64::from(LOOPBACK_WORD)),
            V(request),
            V(11),
            V(0),
            V(reply),
            V(8),
            V(500),
        ],
    );
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(87);

    p.call(CLOSE, &[M(handle)]);
    p.eax(1);
    p.call(CLOSE, &[M(handle)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(6);
    p.finish()
}

/// `DnsQuery_W`: the guest's own catalog answers for its own name, an absent
/// name is reported absent, and the published record chain is walked through
/// the pointers the model wrote.
fn network_dns(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            (
                "dnsapi.dll",
                vec!["DnsQuery_W".into(), "DnsRecordListFree".into()],
            ),
            ("kernel32.dll", vec!["lstrcmpW".into()]),
        ],
    );
    const QUERY: usize = 0;
    const FREE: usize = 1;
    const COMPARE: usize = 2;

    let w = width(&p);
    let header = 2 * w + 16;
    let host = p.string(HOST_NAME);
    let expected = p.string("desktop-7f4m2q9");
    let missing = p.string("no-such-host.invalid");
    let records = p.scratch(16);
    let name = p.scratch(16);

    // The machine's own name answers with the adapter address.
    p.set_dword(records, 0);
    p.call(QUERY, &[V(host), V(1), V(0), V(0), V(records), V(0)]);
    p.eax(0);
    p.indirect_dword(records, 0, 0);
    // Record type A and a four-byte address, in the one word they share.
    p.indirect_dword(records, 2 * w, 0x0004_0001);
    // Section answer, character set Unicode.
    p.indirect_dword(records, 2 * w + 4, 1 | (1 << 3));
    p.indirect_dword(records, 2 * w + 8, 60);
    p.indirect_dword(records, header, HOST_WORD);
    // The record's own name is the normalized name that was queried.
    p.indirect(records, w, name);
    p.call(COMPARE, &[M(name), V(expected)]);
    p.eax(0);
    p.call(FREE, &[M(records), V(1)]);

    // A name the catalog does not carry is reported absent, with nothing
    // published; the same name with no record of that type says so instead.
    p.set_dword(records, 0);
    p.call(QUERY, &[V(missing), V(1), V(0), V(0), V(records), V(0)]);
    p.eax(9003);
    p.dword(records, 0);
    p.call(QUERY, &[V(host), V(28), V(0), V(0), V(records), V(0)]);
    p.eax(9501);
    p.dword(records, 0);
    // An explicit server list would need a network, and the reserved
    // argument must be null.
    p.call(QUERY, &[V(host), V(1), V(0), V(host), V(records), V(0)]);
    p.eax(50);
    p.call(QUERY, &[V(host), V(1), V(0), V(0), V(records), V(host)]);
    p.eax(87);
    p.finish()
}

/// Join and workstation information, and the recorded account creation.
fn network_workstation(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            (
                "netapi32.dll",
                vec![
                    "NetGetJoinInformation".into(),
                    "NetWkstaGetInfo".into(),
                    "NetUserAdd".into(),
                    "NetApiBufferFree".into(),
                ],
            ),
            ("kernel32.dll", vec!["lstrcmpW".into()]),
        ],
    );
    const JOIN: usize = 0;
    const WKSTA: usize = 1;
    const USER_ADD: usize = 2;
    const FREE: usize = 3;
    const COMPARE: usize = 4;

    let w = width(&p);
    let group = p.string(WORKGROUP);
    let host = p.string(HOST_NAME);
    let account = p.string("svc-backdoor");
    let secret = p.string("Pa55w0rd!");
    let name = p.scratch(16);
    let kind = p.scratch(16);
    let info = p.scratch(16);
    let field = p.scratch(16);
    let user = p.scratch(64);

    // A workgroup persona reports its workgroup name, not a domain.
    p.poison(kind, 1);
    p.call(JOIN, &[V(0), V(name), V(kind)]);
    p.eax(0);
    p.dword(kind, 2);
    p.call(COMPARE, &[M(name), V(group)]);
    p.eax(0);
    p.call(FREE, &[M(name)]);
    p.eax(0);
    // A buffer this allocator no longer owns is refused.
    p.call(FREE, &[M(name)]);
    p.eax(87);

    // Level 100 workstation information: an NT platform running 10.0.
    p.call(WKSTA, &[V(0), V(100), V(info)]);
    p.eax(0);
    p.indirect_dword(info, 0, 500);
    p.indirect_dword(info, 3 * w, 10);
    p.indirect_dword(info, 3 * w + 4, 0);
    p.indirect(info, w, field);
    p.call(COMPARE, &[M(field), V(host)]);
    p.eax(0);
    p.indirect(info, 2 * w, field);
    p.call(COMPARE, &[M(field), V(group)]);
    p.eax(0);
    p.call(FREE, &[M(info)]);
    p.eax(0);
    // An unsupported level is refused before anything is published.
    p.call(WKSTA, &[V(0), V(99), V(info)]);
    p.eax(124);

    // The account-creation attempt is observed in full and creates nothing.
    set_pointer(&mut p, user, account);
    set_pointer(&mut p, user + w, secret);
    p.set_dword(user + 2 * w, 0);
    p.set_dword(user + 2 * w + 4, 2);
    set_pointer(&mut p, user + 2 * w + 8, 0);
    set_pointer(&mut p, user + 3 * w + 8, 0);
    p.set_dword(user + 4 * w + 8, 0x0201);
    set_pointer(&mut p, user + 4 * w + 16, 0);
    p.call(USER_ADD, &[V(0), V(1), V(user), V(0)]);
    p.eax(0);
    p.finish()
}

/// The network redirector: a share mapping attempt, a browse attempt and the
/// connection queries, each answered with what an offline machine reports.
fn network_redirector(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[(
            "mpr.dll",
            vec![
                "WNetAddConnection2W".into(),
                "WNetOpenEnumW".into(),
                "WNetEnumResourceW".into(),
                "WNetGetConnectionW".into(),
            ],
        )],
    );
    const ADD: usize = 0;
    const OPEN: usize = 1;
    const ENUM: usize = 2;
    const GET: usize = 3;

    let w = width(&p);
    let share = p.string("\\\\10.0.2.20\\payroll");
    let local = p.string("Z:");
    let bogus = p.string("not-a-device");
    let user = p.string("WORKGROUP\\admin");
    let secret = p.string("Pa55w0rd!");
    let resource = p.scratch(64);
    let handle = p.scratch(16);
    let count = p.scratch(16);
    let size = p.scratch(16);
    let buffer = p.scratch(64);

    // NETRESOURCE: a disk share to be mapped on Z:.
    p.set_dword(resource, 2);
    p.set_dword(resource + 4, 1);
    p.set_dword(resource + 8, 0);
    p.set_dword(resource + 12, 1);
    set_pointer(&mut p, resource + 16, local);
    let remote = 16 + w;
    set_pointer(&mut p, resource + remote, share);
    set_pointer(&mut p, resource + remote + w, 0);
    set_pointer(&mut p, resource + remote + 2 * w, 0);

    // The attempt is recorded in full, then the network reports itself absent.
    p.call(ADD, &[V(resource), V(secret), V(user), V(0)]);
    p.eax(1222);
    // A remote name that is not a UNC path is a bad network name.
    set_pointer(&mut p, resource + remote, local);
    p.call(ADD, &[V(resource), V(0), V(0), V(0)]);
    p.eax(67);

    // No enumeration handle is ever issued, so none can be walked.
    p.poison(handle, 1);
    p.call(OPEN, &[V(2), V(1), V(0), V(0), V(handle)]);
    p.eax(1222);
    p.intact(handle, 1);
    p.set_dword(count, 1);
    p.set_dword(size, 64);
    p.call(ENUM, &[V(0x1234), V(count), V(buffer), V(size)]);
    p.eax(6);

    // The guest's only volume is local, so no device is redirected, and a
    // string that is not a device at all is refused as one.
    p.set_dword(size, 64);
    p.call(GET, &[V(local), V(buffer), V(size)]);
    p.eax(2250);
    p.call(GET, &[V(bogus), V(buffer), V(size)]);
    p.eax(1200);
    p.finish()
}

/// `InternetCrackUrl` in both documented modes: pointers into the caller's own
/// URL, and copies into the buffers it supplied.
fn network_crack_url(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        false,
        &[
            ("wininet.dll", vec!["InternetCrackUrlA".into()]),
            ("kernel32.dll", vec!["GetLastError".into()]),
        ],
    );
    const CRACK: usize = 0;
    const LASTERROR: usize = 1;

    let w = width(&p);
    let url = p.ascii("https://files.example:8443/drop/p.bin?id=7");
    let plain = p.ascii("not-a-url");
    let components = p.scratch(128);
    let host = p.scratch(64);

    // URL_COMPONENTS offsets for this width.
    let size = if p.wide { 104u32 } else { 60 };
    let scheme = w;
    let scheme_length = 2 * w;
    let number = 2 * w + 4;
    let host_at = 2 * w + 8;
    let host_length = host_at + w;
    let port = host_length + 4;
    let path = if p.wide { 72u64 } else { 44 };
    let path_length = path + w;
    let extra_length = if p.wide { 96u64 } else { 56 };

    // Pointer mode: every component pointer is null and every length zero, so
    // the answer points into the caller's own URL text.
    p.set_dword(components, size);
    for index in 1..u64::from(size) / 4 {
        p.set_dword(components + index * 4, 0);
    }
    p.call(CRACK, &[V(url), V(0), V(0), V(components)]);
    p.eax(1);
    // INTERNET_SCHEME_HTTPS, the explicit port, and each component's text
    // inside the URL the caller passed.
    p.dword(components + number, 4);
    p.dword(components + port, 8443);
    p.dword(components + scheme, url as u32);
    p.dword(components + scheme_length, 5);
    p.dword(components + host_at, (url + 8) as u32);
    p.dword(components + host_length, 13);
    p.dword(components + path, (url + 26) as u32);
    p.dword(components + path_length, 11);
    p.dword(components + extra_length, 5);

    // Buffer mode: the structure is cleared again — pointer mode left every
    // component addressing the URL — and only the host buffer is supplied, so
    // that component is copied with its terminator while the rest answer as
    // lengths again. A buffer one character short is refused.
    for index in 1..u64::from(size) / 4 {
        p.set_dword(components + index * 4, 0);
    }
    set_pointer(&mut p, components + host_at, host);
    p.set_dword(components + host_length, 64);
    p.poison(host, 5);
    p.call(CRACK, &[V(url), V(0), V(0), V(components)]);
    p.eax(1);
    p.ascii_text(host, "files.example");
    p.dword(components + host_length, 13);

    // A buffer one character short is refused and learns the length it
    // needed, terminator included. The structure is cleared once more first:
    // the last call left the other components addressing the URL, and one of
    // those would be the short buffer instead.
    for index in 1..u64::from(size) / 4 {
        p.set_dword(components + index * 4, 0);
    }
    set_pointer(&mut p, components + host_at, host);
    p.set_dword(components + host_length, 13);
    p.call(CRACK, &[V(url), V(0), V(0), V(components)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(122);
    p.dword(components + host_length, 14);

    // Text that is not a URL is not cracked into one.
    p.set_dword(components, size);
    p.call(CRACK, &[V(plain), V(0), V(0), V(components)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(12006);
    // A structure size that is not the real one is refused.
    p.set_dword(components, 8);
    p.call(CRACK, &[V(url), V(0), V(0), V(components)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(87);
    p.finish()
}

/// WinINet handle options: the handle type, the documented defaults, a round
/// trip through a set, the refusal of an option outside the profile, and the
/// connected-state and error-dialog answers.
fn network_options(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        false,
        &[
            (
                "wininet.dll",
                vec![
                    "InternetOpenA".into(),
                    "InternetQueryOptionA".into(),
                    "InternetSetOptionA".into(),
                    "InternetGetConnectedState".into(),
                    "InternetErrorDlg".into(),
                    "InternetCloseHandle".into(),
                ],
            ),
            ("kernel32.dll", vec!["GetLastError".into()]),
        ],
    );
    const OPEN: usize = 0;
    const QUERY: usize = 1;
    const SET: usize = 2;
    const CONNECTED: usize = 3;
    const ERROR_DIALOG: usize = 4;
    const CLOSE: usize = 5;
    const LASTERROR: usize = 6;

    let agent = p.ascii("Emumee/1.0");
    let session = p.scratch(16);
    let value = p.scratch(16);
    let length = p.scratch(16);
    let buffer = p.scratch(64);

    // A configured LAN connection, and the reserved argument must be zero.
    p.poison(value, 1);
    p.call(CONNECTED, &[V(value), V(0)]);
    p.eax(1);
    p.dword(value, 0x42);
    p.call(CONNECTED, &[V(value), V(1)]);
    p.eax(0);

    // There is no interactive user: the no-UI flag succeeds and anything that
    // would have shown a dialog counts as cancelled.
    p.call(ERROR_DIALOG, &[V(0), V(0), V(12045), V(8), V(0)]);
    p.eax(0);
    p.call(ERROR_DIALOG, &[V(0), V(0), V(12045), V(0), V(0)]);
    p.eax(1223);

    p.call(OPEN, &[V(agent), V(1), V(0), V(0), V(0)]);
    p.opened();
    p.save(session);

    // The session reports its own handle type and the agent it opened with.
    p.set_dword(length, 4);
    p.call(QUERY, &[M(session), V(9), V(value), V(length)]);
    p.eax(1);
    p.dword(value, 1);
    p.dword(length, 4);
    p.set_dword(length, 64);
    p.poison(buffer, 4);
    p.call(QUERY, &[M(session), V(41), V(buffer), V(length)]);
    p.eax(1);
    p.ascii_text(buffer, "Emumee/1.0");
    p.dword(length, 11);

    // A connect timeout reads its documented default, then the value that was
    // set, and a short buffer learns the size it needed.
    p.set_dword(length, 4);
    p.call(QUERY, &[M(session), V(2), V(value), V(length)]);
    p.eax(1);
    p.dword(value, 60000);
    p.set_dword(value, 7500);
    p.call(SET, &[M(session), V(2), V(value), V(4)]);
    p.eax(1);
    p.set_dword(value, 0);
    p.set_dword(length, 4);
    p.call(QUERY, &[M(session), V(2), V(value), V(length)]);
    p.eax(1);
    p.dword(value, 7500);
    p.set_dword(length, 2);
    p.call(QUERY, &[M(session), V(2), V(value), V(length)]);
    p.eax(0);
    p.dword(length, 4);
    p.call(LASTERROR, &[]);
    p.eax(122);

    // An option outside this profile is refused rather than answered.
    p.set_dword(length, 4);
    p.call(QUERY, &[M(session), V(1), V(value), V(length)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(12009);
    p.call(SET, &[M(session), V(1), V(value), V(4)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(12009);

    p.call(CLOSE, &[M(session)]);
    p.eax(1);
    p.finish()
}

/// WinHTTP URL cracking, the IE proxy configuration, proxy autodetection,
/// options and request headers.
fn network_winhttp(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        true,
        &[
            (
                "winhttp.dll",
                vec![
                    "WinHttpCrackUrl".into(),
                    "WinHttpGetIEProxyConfigForCurrentUser".into(),
                    "WinHttpOpen".into(),
                    "WinHttpGetProxyForUrl".into(),
                    "WinHttpSetOption".into(),
                    "WinHttpConnect".into(),
                    "WinHttpOpenRequest".into(),
                    "WinHttpAddRequestHeaders".into(),
                    "WinHttpCloseHandle".into(),
                ],
            ),
            ("kernel32.dll", vec!["GetLastError".into()]),
        ],
    );
    const CRACK: usize = 0;
    const IE_PROXY: usize = 1;
    const OPEN: usize = 2;
    const PROXY_FOR_URL: usize = 3;
    const SET_OPTION: usize = 4;
    const CONNECT: usize = 5;
    const REQUEST: usize = 6;
    const ADD_HEADERS: usize = 7;
    const CLOSE: usize = 8;
    const LASTERROR: usize = 9;

    let w = width(&p);
    let url = p.string("http://files.example/drop");
    let credentials = p.string("http://alex:secret@files.example/drop");
    let host = p.string("files.example");
    let path = p.string("/drop");
    let header = p.string("X-Tag: one\r\n");
    let replacement = p.string("X-Tag: two\r\n");
    let removal = p.string("X-Tag:\r\n");
    let components = p.scratch(128);
    let config = p.scratch(64);
    let options = p.scratch(64);
    let proxy = p.scratch(64);
    let session = p.scratch(16);
    let connection = p.scratch(16);
    let request = p.scratch(16);
    let value = p.scratch(16);

    let size = if p.wide { 104u32 } else { 60 };
    let number = 2 * w + 4;
    let host_at = 2 * w + 8;
    let host_length = host_at + w;
    let port = host_length + 4;

    // Pointer mode, wide: the scheme, the default port and the host inside
    // the caller's own URL.
    p.set_dword(components, size);
    for index in 1..u64::from(size) / 4 {
        p.set_dword(components + index * 4, 0);
    }
    p.call(CRACK, &[V(url), V(0), V(0), V(components)]);
    p.eax(1);
    p.dword(components + number, 3);
    p.dword(components + port, 80);
    p.dword(components + host_at, (url + 14) as u32);
    p.dword(components + host_length, 13);
    // ICU_REJECT_USERPWD refuses a URL that carries credentials.
    p.set_dword(components, size);
    p.call(CRACK, &[V(credentials), V(0), V(0x4000), V(components)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(12005);

    // The IE proxy configuration is a direct connection: no automatic
    // detection, no script URL, no proxy and no bypass list.
    p.poison(config, 8);
    p.call(IE_PROXY, &[V(config)]);
    p.eax(1);
    p.dword(config, 0);
    p.dword(config + w, 0);
    p.dword(config + 2 * w, 0);
    p.dword(config + 3 * w, 0);

    p.call(OPEN, &[V(0), V(1), V(0), V(0), V(0)]);
    p.opened();
    p.save(session);

    // WPAD autodetection has nothing to find here, and the URL asked about is
    // recorded rather than answered with an invented proxy.
    p.set_dword(options, 1);
    p.set_dword(options + 4, 3);
    set_pointer(&mut p, options + 8, 0);
    p.call(PROXY_FOR_URL, &[M(session), V(url), V(options), V(proxy)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(12180);

    // A documented option is accepted; one outside the profile is refused.
    p.set_dword(value, 15000);
    p.call(SET_OPTION, &[M(session), V(6), V(value), V(4)]);
    p.eax(1);
    p.call(SET_OPTION, &[M(session), V(999), V(value), V(4)]);
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(12009);

    // Request headers: added, refused as already present, replaced and
    // removed, exactly as the modifiers document.
    p.call(CONNECT, &[M(session), V(host), V(80), V(0)]);
    p.opened();
    p.save(connection);
    p.call(
        REQUEST,
        &[M(connection), V(0), V(path), V(0), V(0), V(0), V(0)],
    );
    p.opened();
    p.save(request);
    p.call(
        ADD_HEADERS,
        &[M(request), V(header), V(0xFFFF_FFFF), V(0x2000_0000)],
    );
    p.eax(1);
    p.call(
        ADD_HEADERS,
        &[M(request), V(header), V(0xFFFF_FFFF), V(0x1000_0000)],
    );
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(12155);
    p.call(
        ADD_HEADERS,
        &[M(request), V(replacement), V(0xFFFF_FFFF), V(0x8000_0000)],
    );
    p.eax(1);
    p.call(
        ADD_HEADERS,
        &[M(request), V(removal), V(0xFFFF_FFFF), V(0x8000_0000)],
    );
    p.eax(1);
    p.call(
        ADD_HEADERS,
        &[M(request), V(removal), V(0xFFFF_FFFF), V(0x8000_0000)],
    );
    p.eax(0);
    p.call(LASTERROR, &[]);
    p.eax(12150);

    p.call(CLOSE, &[M(session)]);
    p.eax(1);
    p.finish()
}
