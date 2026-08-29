//! Message digests (FIPS 180-4, FIPS 202, RFC 1321) and HMAC (RFC 2104).

use crate::{CryptoError, Result};
use hmac::{Mac, SimpleHmac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_256;
use wasm_bindgen::prelude::*;

/// Algorithm identifiers accepted by `digest` and `hmac`.
pub const ALGORITHMS: [&str; 5] = ["md5", "sha1", "sha256", "sha512", "sha3-256"];

fn unknown(alg: &str) -> CryptoError {
    CryptoError::new(format!("Unknown algorithm '{alg}' (md5, sha1, sha256, sha512, sha3-256)"))
}

pub fn digest_bytes(alg: &str, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match alg {
        "md5" => Md5::digest(data).to_vec(),
        "sha1" => Sha1::digest(data).to_vec(),
        "sha256" => Sha256::digest(data).to_vec(),
        "sha512" => Sha512::digest(data).to_vec(),
        "sha3-256" => Sha3_256::digest(data).to_vec(),
        _ => return Err(unknown(alg)),
    })
}

fn mac<D: Digest + hmac::digest::core_api::BlockSizeUser + Clone>(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC accepts any key length: longer keys are hashed, shorter ones padded.
    let mut m = <SimpleHmac<D> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

pub fn hmac_bytes(alg: &str, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    Ok(match alg {
        "md5" => mac::<Md5>(key, data),
        "sha1" => mac::<Sha1>(key, data),
        "sha256" => mac::<Sha256>(key, data),
        "sha512" => mac::<Sha512>(key, data),
        "sha3-256" => mac::<Sha3_256>(key, data),
        _ => return Err(unknown(alg)),
    })
}

#[wasm_bindgen]
pub struct Hasher;

#[wasm_bindgen]
impl Hasher {
    /// Hex digest of `data` under `alg`.
    pub fn digest(alg: &str, data: &[u8]) -> Result<String> {
        digest_bytes(alg, data).map(hex::encode)
    }

    /// Hex HMAC tag of `data` under `key` and `alg`.
    pub fn hmac(alg: &str, key: &[u8], data: &[u8]) -> Result<String> {
        hmac_bytes(alg, key, data).map(hex::encode)
    }

    /// Supported algorithm identifiers.
    pub fn algorithms() -> Vec<String> {
        ALGORITHMS.iter().map(|s| s.to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_known_answers_for_abc() {
        let cases = [
            ("md5", "900150983cd24fb0d6963f7d28e17f72"),
            ("sha1", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ("sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("sha512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            ("sha3-256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        ];
        for (alg, expected) in cases {
            assert_eq!(Hasher::digest(alg, b"abc").unwrap(), expected, "{alg}");
        }
        assert!(Hasher::digest("crc32", b"abc").is_err());
    }

    #[test]
    fn hmac_rfc_2202_and_4231_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        assert_eq!(Hasher::hmac("md5", key, data).unwrap(), "750c783e6ab0b503eaa86e310a5db738");
        assert_eq!(Hasher::hmac("sha1", key, data).unwrap(), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        assert_eq!(Hasher::hmac("sha256", key, data).unwrap(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(Hasher::hmac("sha512", key, data).unwrap(), "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
        // Empty and over-long keys are accepted (RFC 2104 §2).
        assert!(Hasher::hmac("sha256", b"", data).is_ok());
        assert!(Hasher::hmac("sha256", &[7u8; 200], data).is_ok());
    }
}
