//! Cryptography control family: owned-primitive hashing, deterministic random
//! streams, base64/hex decoding, RC4 key derivation and in-place decryption,
//! and the CNG provider/property/handle surface.
use super::*;
use emumee_core::fixtures::{M7CryptoFixture as F, m7_crypto_probe};

fn control(arch: Architecture, kind: F) -> Execution {
    let label = format!("{arch:?}-m7-crypto-{kind:?}");
    let result = run(&label, m7_crypto_probe(arch, kind), &[], 60_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m7_crypto_hash_random_decode_rc4_and_cng_are_guest_decided() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Hash, F::Random, F::Decode, F::Rc4, F::Cng] {
            let result = control(arch, kind);
            // Crypto operates on guest memory only; no artifact or capture is
            // produced and the network is never reached.
            assert!(result.artifacts.is_empty(), "{kind:?}: {:?}", result.artifacts);
            assert_eq!(result.network.calls, 0);
        }
    }
}
