//! Cryptography model: the legacy CryptoAPI hash/key/random surface
//! (`advapi32`), the base64/hex decoder (`crypt32`), the deterministic random
//! providers (`SystemFunction036`, `ProcessPrng`) and the CNG provider/key
//! handle surface (`bcrypt`, `ncrypt`).
//!
//! For a malware-analysis runtime cryptography is observed, not refused: digests
//! are computed with owned deterministic primitives, randomness comes from a
//! fixed-seed stream so output is reproducible between a run and its replay (and
//! never derived from the host clock), RC4 decryption is carried out for real,
//! and base64/hex payloads are decoded. CNG provider and key objects are modeled
//! as observable handles so an import is recorded rather than failing the guest.
use super::*;
use emumee_core::crypto::{Rc4, md5, sha1};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::{BTreeMap, BTreeSet};

// CryptoAPI algorithm ids.
const CALG_MD5: u32 = 0x8003;
const CALG_SHA1: u32 = 0x8004;
const CALG_SHA_256: u32 = 0x800c;
const CALG_SHA_384: u32 = 0x800d;
const CALG_SHA_512: u32 = 0x800e;
const CALG_RC4: u32 = 0x6801;

// CryptGetHashParam selectors.
const HP_ALGID: u32 = 1;
const HP_HASHVAL: u32 = 2;
const HP_HASHSIZE: u32 = 4;

// CryptStringToBinary format (low nibble of dwFlags).
const CRYPT_STRING_BASE64: u32 = 0x1;
const CRYPT_STRING_HEX: u32 = 0x4;
const CRYPT_STRING_HEXRAW: u32 = 0xc;

// Errors.
const NTE_BAD_ALGID: u32 = 0x8009_0008;
const NTE_BAD_HASH: u32 = 0x8009_0002;
const NTE_BAD_KEY: u32 = 0x8009_0003;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_INVALID_PARAMETER: u32 = 87;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_0002;

#[derive(Clone, Debug)]
struct Hash {
    alg: u32,
    data: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Key {
    alg: u32,
    material: Vec<u8>,
    stream: Option<Rc4>,
}

/// All crypto objects, keyed by the opaque handles the model hands out.
#[derive(Default)]
pub(crate) struct State {
    counter: u64,
    prng: u64,
    contexts: BTreeSet<u64>,
    hashes: BTreeMap<u64, Hash>,
    keys: BTreeMap<u64, Key>,
    bcrypt_algs: BTreeMap<u64, String>,
    bcrypt_keys: BTreeSet<u64>,
    ncrypt_providers: BTreeSet<u64>,
    ncrypt_keys: BTreeSet<u64>,
}

impl State {
    fn handle(&mut self) -> u64 {
        self.counter += 1;
        // Distinctive, non-null, 32-bit-safe handle values.
        0x4A50_0000 + self.counter * 0x40
    }

    /// Fixed-seed SplitMix64 stream: deterministic and clock-independent.
    fn random(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            self.prng = self.prng.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.prng;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    AcquireContext { wide: bool },
    ReleaseContext,
    CreateHash,
    HashData,
    GetHashParam,
    DestroyHash,
    DeriveKey,
    Decrypt,
    GenRandom,
    /// `SystemFunction036`/`RtlGenRandom`: `(buffer, len)`.
    RtlGenRandom,
    /// `ProcessPrng`: `(buffer, len)`.
    ProcessPrng,
    StringToBinary { wide: bool },
    BCryptOpen,
    BCryptGetProperty,
    BCryptImportKeyPair,
    BCryptDestroyKey,
    BCryptClose,
    NCryptOpen,
    NCryptImportKey,
    NCryptDeleteKey,
    NCryptFreeObject,
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, C, T)> {
    use Call::*;
    let call = match (module, name) {
        ("advapi32", "CryptAcquireContextA") => (AcquireContext { wide: false }, 5),
        ("advapi32", "CryptAcquireContextW") => (AcquireContext { wide: true }, 5),
        ("advapi32", "CryptReleaseContext") => (ReleaseContext, 2),
        ("advapi32", "CryptCreateHash") => (CreateHash, 5),
        ("advapi32", "CryptHashData") => (HashData, 4),
        ("advapi32", "CryptGetHashParam") => (GetHashParam, 5),
        ("advapi32", "CryptDestroyHash") => (DestroyHash, 1),
        ("advapi32", "CryptDeriveKey") => (DeriveKey, 5),
        ("advapi32", "CryptDecrypt") => (Decrypt, 6),
        ("advapi32", "CryptGenRandom") => (GenRandom, 3),
        ("advapi32" | "cryptbase", "SystemFunction036") => (RtlGenRandom, 2),
        ("bcryptprimitives" | "cryptbase", "ProcessPrng") => (ProcessPrng, 2),
        ("crypt32", "CryptStringToBinaryA") => (StringToBinary { wide: false }, 7),
        ("crypt32", "CryptStringToBinaryW") => (StringToBinary { wide: true }, 7),
        ("bcrypt", "BCryptOpenAlgorithmProvider") => (BCryptOpen, 4),
        ("bcrypt", "BCryptGetProperty") => (BCryptGetProperty, 6),
        ("bcrypt", "BCryptImportKeyPair") => (BCryptImportKeyPair, 7),
        ("bcrypt", "BCryptDestroyKey") => (BCryptDestroyKey, 1),
        ("bcrypt", "BCryptCloseAlgorithmProvider") => (BCryptClose, 2),
        ("ncrypt", "NCryptOpenStorageProvider") => (NCryptOpen, 3),
        ("ncrypt", "NCryptImportKey") => (NCryptImportKey, 8),
        ("ncrypt", "NCryptDeleteKey") => (NCryptDeleteKey, 2),
        ("ncrypt", "NCryptFreeObject") => (NCryptFreeObject, 1),
        _ => return None,
    };
    Some((call.0, call.1, C::Stdcall, T::U32))
}

fn ptr_width(engine: &Unicorn<Trace>) -> usize {
    if engine.get_data().architecture == Architecture::X64 {
        8
    } else {
        4
    }
}

fn read_dword(engine: &Unicorn<Trace>, address: u64) -> Result<u32> {
    let bytes = read(engine, address, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn write_dword(engine: &mut Unicorn<Trace>, address: u64, value: u32) -> Result<()> {
    require(engine, address, 4, P::WRITE)?;
    crate::cpu::write(engine, address, &value.to_le_bytes())
}

fn write_handle(engine: &mut Unicorn<Trace>, address: u64, value: u64) -> Result<()> {
    let width = ptr_width(engine);
    require(engine, address, width as u64, P::WRITE)?;
    crate::cpu::write(engine, address, &value.to_le_bytes()[..width])
}

fn put(engine: &mut Unicorn<Trace>, address: u64, bytes: &[u8]) -> Result<()> {
    require(engine, address, bytes.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, address, bytes)
}

fn fail(engine: &mut Unicorn<Trace>, code: u32) -> Result<u64> {
    engine.get_data_mut().apis.last_error = code;
    Ok(0)
}

/// A CryptoAPI digest, if the algorithm is one this profile computes.
fn digest(alg: u32, data: &[u8]) -> Option<Vec<u8>> {
    Some(match alg {
        CALG_MD5 => md5(data).to_vec(),
        CALG_SHA1 => sha1(data).to_vec(),
        CALG_SHA_256 => Sha256::digest(data).to_vec(),
        CALG_SHA_384 => Sha384::digest(data).to_vec(),
        CALG_SHA_512 => Sha512::digest(data).to_vec(),
        _ => return None,
    })
}

fn digest_size(alg: u32) -> Option<u32> {
    match alg {
        CALG_MD5 => Some(16),
        CALG_SHA1 => Some(20),
        CALG_SHA_256 => Some(32),
        CALG_SHA_384 => Some(48),
        CALG_SHA_512 => Some(64),
        _ => None,
    }
}

/// Wide property name for the CNG property calls.
fn wide_name(engine: &Unicorn<Trace>, address: u64) -> Result<String> {
    if address == 0 {
        return Ok(String::new());
    }
    files::path(engine, address, true)
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    match call {
        Call::AcquireContext { wide } => {
            // CryptAcquireContext(phProv, szContainer, szProvider, type, flags):
            // the container/provider names are observed but a single owned CSP
            // backs every request.
            let _ = wide;
            if args[0] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let handle = engine.get_data_mut().apis.crypto.handle();
            engine.get_data_mut().apis.crypto.contexts.insert(handle);
            write_handle(engine, args[0], handle)?;
            Ok(1)
        }
        Call::ReleaseContext => {
            engine.get_data_mut().apis.crypto.contexts.remove(&args[0]);
            Ok(1)
        }
        Call::CreateHash => {
            // CryptCreateHash(hProv, algId, hKey, flags, phHash).
            let alg = args[1] as u32;
            if digest(alg, &[]).is_none() {
                return fail(engine, NTE_BAD_ALGID);
            }
            let handle = engine.get_data_mut().apis.crypto.handle();
            engine
                .get_data_mut()
                .apis
                .crypto
                .hashes
                .insert(handle, Hash { alg, data: Vec::new() });
            write_handle(engine, args[4], handle)?;
            Ok(1)
        }
        Call::HashData => {
            // CryptHashData(hHash, pbData, dwDataLen, flags).
            let len = args[2] as u32 as u64;
            ensure!(len <= 1 << 24, "CryptHashData length exceeds its modeled bound");
            let bytes = read(engine, args[1], len)?;
            match engine.get_data_mut().apis.crypto.hashes.get_mut(&args[0]) {
                Some(hash) => {
                    hash.data.extend_from_slice(&bytes);
                    Ok(1)
                }
                None => fail(engine, NTE_BAD_HASH),
            }
        }
        Call::GetHashParam => {
            // CryptGetHashParam(hHash, dwParam, pbData, pdwDataLen, flags).
            let Some(hash) = engine.get_data().apis.crypto.hashes.get(&args[0]).cloned() else {
                return fail(engine, NTE_BAD_HASH);
            };
            let value: Vec<u8> = match args[1] as u32 {
                HP_ALGID => hash.alg.to_le_bytes().to_vec(),
                HP_HASHSIZE => digest_size(hash.alg).unwrap().to_le_bytes().to_vec(),
                HP_HASHVAL => digest(hash.alg, &hash.data).unwrap(),
                _ => return fail(engine, ERROR_INVALID_PARAMETER),
            };
            let capacity = read_dword(engine, args[3])?;
            if args[2] == 0 {
                write_dword(engine, args[3], value.len() as u32)?;
                return Ok(1);
            }
            if (capacity as usize) < value.len() {
                write_dword(engine, args[3], value.len() as u32)?;
                return fail(engine, ERROR_MORE_DATA);
            }
            put(engine, args[2], &value)?;
            write_dword(engine, args[3], value.len() as u32)?;
            Ok(1)
        }
        Call::DestroyHash => {
            engine.get_data_mut().apis.crypto.hashes.remove(&args[0]);
            Ok(1)
        }
        Call::DeriveKey => {
            // CryptDeriveKey(hProv, algId, hBaseData, flags, phKey): the key is
            // derived from the base hash value, truncated to the algorithm key
            // length (the high word of dwFlags, in bits, or the default).
            let alg = args[1] as u32;
            let Some(hash) = engine.get_data().apis.crypto.hashes.get(&args[2]).cloned() else {
                return fail(engine, NTE_BAD_HASH);
            };
            let material = digest(hash.alg, &hash.data).unwrap();
            let bits = (args[3] >> 16) as u32 as usize;
            let key_len = if bits != 0 { bits / 8 } else { default_key_len(alg) };
            if key_len == 0 || key_len > material.len() {
                // Longer-than-digest key expansion is not modeled.
                return fail(engine, NTE_BAD_ALGID);
            }
            let handle = engine.get_data_mut().apis.crypto.handle();
            engine.get_data_mut().apis.crypto.keys.insert(
                handle,
                Key {
                    alg,
                    material: material[..key_len].to_vec(),
                    stream: None,
                },
            );
            write_handle(engine, args[4], handle)?;
            Ok(1)
        }
        Call::Decrypt => {
            // CryptDecrypt(hKey, hHash, Final, flags, pbData, pdwDataLen).
            let Some(mut key) = engine.get_data().apis.crypto.keys.get(&args[0]).cloned() else {
                return fail(engine, NTE_BAD_KEY);
            };
            if key.alg != CALG_RC4 {
                // Only the RC4 stream cipher is carried out; block ciphers are
                // not modeled here.
                return fail(engine, NTE_BAD_ALGID);
            }
            let len = read_dword(engine, args[5])?;
            ensure!(len as u64 <= 1 << 24, "CryptDecrypt length exceeds its modeled bound");
            let mut buffer = read(engine, args[4], len as u64)?;
            let stream = key.stream.get_or_insert_with(|| Rc4::new(&key.material));
            stream.apply(&mut buffer);
            put(engine, args[4], &buffer)?;
            // If a hash is attached, the plaintext feeds it, as documented.
            if args[1] != 0 {
                if let Some(hash) = engine.get_data_mut().apis.crypto.hashes.get_mut(&args[1]) {
                    hash.data.extend_from_slice(&buffer);
                }
            }
            engine.get_data_mut().apis.crypto.keys.insert(args[0], key);
            Ok(1)
        }
        Call::GenRandom => {
            // CryptGenRandom(hProv, dwLen, pbBuffer).
            random_into(engine, args[2], args[1] as u32 as u64)?;
            Ok(1)
        }
        Call::RtlGenRandom => {
            // SystemFunction036(pbBuffer, ulLen) -> BOOLEAN.
            random_into(engine, args[0], args[1] as u32 as u64)?;
            Ok(1)
        }
        Call::ProcessPrng => {
            // ProcessPrng(pbData, cbData) -> BOOL.
            random_into(engine, args[0], args[1] as u32 as u64)?;
            Ok(1)
        }
        Call::StringToBinary { wide } => string_to_binary(engine, args, wide),
        Call::BCryptOpen => {
            // BCryptOpenAlgorithmProvider(phAlgorithm, pszAlgId, impl, flags).
            let alg = wide_name(engine, args[1])?.to_ascii_uppercase();
            let handle = engine.get_data_mut().apis.crypto.handle();
            engine.get_data_mut().apis.crypto.bcrypt_algs.insert(handle, alg);
            write_handle(engine, args[0], handle)?;
            Ok(0)
        }
        Call::BCryptGetProperty => {
            // BCryptGetProperty(hObject, pszProperty, pbOutput, cbOutput,
            // pcbResult, flags).
            let Some(alg) = engine.get_data().apis.crypto.bcrypt_algs.get(&args[0]).cloned() else {
                return Ok(STATUS_NOT_SUPPORTED as u64);
            };
            let property = wide_name(engine, args[1])?;
            let value: u32 = match property.as_str() {
                // A fixed, plausible per-object scratch length.
                "ObjectLength" => 0x300,
                "HashDigestLength" => cng_digest_length(&alg).unwrap_or(0),
                "BlockLength" => 16,
                _ => return Ok(STATUS_NOT_SUPPORTED as u64),
            };
            if property == "HashDigestLength" && value == 0 {
                return Ok(STATUS_NOT_SUPPORTED as u64);
            }
            write_dword(engine, args[4], 4)?;
            if args[2] != 0 {
                if (args[3] as u32) < 4 {
                    return Ok(STATUS_NOT_SUPPORTED as u64);
                }
                write_dword(engine, args[2], value)?;
            }
            Ok(0)
        }
        Call::BCryptImportKeyPair => {
            // BCryptImportKeyPair(hAlg, hImport, blobType, phKey, input, len,
            // flags): the key blob is observed; a handle is issued.
            let handle = engine.get_data_mut().apis.crypto.handle();
            engine.get_data_mut().apis.crypto.bcrypt_keys.insert(handle);
            write_handle(engine, args[3], handle)?;
            Ok(0)
        }
        Call::BCryptDestroyKey => {
            engine.get_data_mut().apis.crypto.bcrypt_keys.remove(&args[0]);
            Ok(0)
        }
        Call::BCryptClose => {
            engine.get_data_mut().apis.crypto.bcrypt_algs.remove(&args[0]);
            Ok(0)
        }
        Call::NCryptOpen => {
            // NCryptOpenStorageProvider(phProvider, pszProviderName, flags).
            let handle = engine.get_data_mut().apis.crypto.handle();
            engine.get_data_mut().apis.crypto.ncrypt_providers.insert(handle);
            write_handle(engine, args[0], handle)?;
            Ok(0)
        }
        Call::NCryptImportKey => {
            // NCryptImportKey(hProv, hImport, blobType, params, phKey, data,
            // len, flags).
            let handle = engine.get_data_mut().apis.crypto.handle();
            engine.get_data_mut().apis.crypto.ncrypt_keys.insert(handle);
            write_handle(engine, args[4], handle)?;
            Ok(0)
        }
        Call::NCryptDeleteKey => {
            engine.get_data_mut().apis.crypto.ncrypt_keys.remove(&args[0]);
            Ok(0)
        }
        Call::NCryptFreeObject => {
            let handle = args[0];
            let state = &mut engine.get_data_mut().apis.crypto;
            state.ncrypt_providers.remove(&handle);
            state.ncrypt_keys.remove(&handle);
            Ok(0)
        }
    }
}

fn default_key_len(alg: u32) -> usize {
    match alg {
        CALG_RC4 => 16,
        0x6601 => 8,  // CALG_DES
        0x6603 => 24, // CALG_3DES
        0x660e => 16, // CALG_AES_128
        0x660f => 24, // CALG_AES_192
        0x6610 => 32, // CALG_AES_256
        _ => 0,
    }
}

fn cng_digest_length(alg: &str) -> Option<u32> {
    match alg {
        "MD5" => Some(16),
        "SHA1" => Some(20),
        "SHA256" => Some(32),
        "SHA384" => Some(48),
        "SHA512" => Some(64),
        _ => None,
    }
}

fn random_into(engine: &mut Unicorn<Trace>, address: u64, len: u64) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    ensure!(len <= 1 << 20, "Random request exceeds its modeled bound");
    require(engine, address, len, P::WRITE)?;
    let mut buffer = vec![0u8; len as usize];
    engine.get_data_mut().apis.crypto.random(&mut buffer);
    crate::cpu::write(engine, address, &buffer)
}

/// `CryptStringToBinary(pszString, cchString, flags, pbBinary, pcbBinary,
/// pdwSkip, pdwFlags)`: base64 or hex decode into `pbBinary`.
fn string_to_binary(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    let text = read_input(engine, args[0], args[1] as u32, wide)?;
    let format = args[2] as u32 & 0xf;
    let decoded = match format {
        CRYPT_STRING_BASE64 => decode_base64(&text),
        CRYPT_STRING_HEX | CRYPT_STRING_HEXRAW => decode_hex(&text),
        _ => None,
    };
    let Some(decoded) = decoded else {
        return fail(engine, ERROR_INVALID_PARAMETER);
    };
    // pcbBinary is in/out: NULL buffer asks for the size.
    if args[3] == 0 {
        write_dword(engine, args[4], decoded.len() as u32)?;
        if args[5] != 0 {
            write_dword(engine, args[5], 0)?;
        }
        return Ok(1);
    }
    let capacity = read_dword(engine, args[4])?;
    if (capacity as usize) < decoded.len() {
        write_dword(engine, args[4], decoded.len() as u32)?;
        return fail(engine, ERROR_MORE_DATA);
    }
    put(engine, args[3], &decoded)?;
    write_dword(engine, args[4], decoded.len() as u32)?;
    if args[5] != 0 {
        write_dword(engine, args[5], 0)?;
    }
    if args[6] != 0 {
        write_dword(engine, args[6], format)?;
    }
    Ok(1)
}

fn read_input(engine: &Unicorn<Trace>, address: u64, count: u32, wide: bool) -> Result<String> {
    if count == 0 {
        return files::path(engine, address, wide);
    }
    let width = if wide { 2 } else { 1 };
    let bytes = read(engine, address, count as u64 * width)?;
    if wide {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&units))
    } else {
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let stripped: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(stripped).ok()
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_digit(16).map(|d| d as u8))
        .collect::<Option<Vec<u8>>>()?;
    if digits.len() % 2 != 0 {
        return None;
    }
    Some(digits.chunks_exact(2).map(|p| (p[0] << 4) | p[1]).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_match_known_answers() {
        assert_eq!(
            digest(CALG_MD5, b"abc").unwrap(),
            hex_bytes("900150983cd24fb0d6963f7d28e17f72")
        );
        assert_eq!(
            digest(CALG_SHA1, b"abc").unwrap(),
            hex_bytes("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            digest(CALG_SHA_256, b"abc").unwrap(),
            hex_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert!(digest(0x1234, b"abc").is_none());
    }

    #[test]
    fn base64_and_hex_decode_round_trip() {
        assert_eq!(decode_base64("YWJj").unwrap(), b"abc");
        assert_eq!(decode_base64("YW Jj\n").unwrap(), b"abc");
        assert!(decode_base64("not valid %%%").is_none());
        assert_eq!(decode_hex("61 62 63").unwrap(), b"abc");
        assert_eq!(decode_hex("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(decode_hex("ABC").is_none());
    }

    #[test]
    fn random_stream_is_deterministic_and_nonrepeating() {
        let mut a = State::default();
        let mut b = State::default();
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        a.random(&mut first);
        b.random(&mut second);
        // Two fresh states produce the same clock-independent stream.
        assert_eq!(first, second);
        // Successive draws differ, so the stream advances.
        let mut third = [0u8; 32];
        a.random(&mut third);
        assert_ne!(first, third);
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
}
