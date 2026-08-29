//! Password strength estimation and password-based key derivation
//! (PBKDF2, RFC 8018; Argon2id, RFC 9106).

use crate::{CryptoError, Result};
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

/// The 1,000 most common passwords from the xato-net 10-million corpus, via
/// SecLists (MIT). One per line, most common first.
const TOP_1000: &str = include_str!("../data/top-1000-passwords.txt");

#[wasm_bindgen]
pub struct PasswordSecurity;

#[wasm_bindgen]
impl PasswordSecurity {
    /// Shannon-style upper bound: length × log₂(alphabet size), where the
    /// alphabet is the union of the character classes present.
    pub fn calculate_entropy(password: &str) -> f64 {
        let len = password.chars().count() as f64;
        Self::alphabet_size(password).map(|pool| len * (pool as f64).log2()).unwrap_or(0.0)
    }

    /// Size of the alphabet implied by the character classes used.
    pub fn alphabet_size(password: &str) -> Option<u32> {
        let mut pool = 0u32;
        if password.chars().any(|c| c.is_ascii_lowercase()) { pool += 26; }
        if password.chars().any(|c| c.is_ascii_uppercase()) { pool += 26; }
        if password.chars().any(|c| c.is_ascii_digit()) { pool += 10; }
        if password.chars().any(|c| c.is_ascii() && !c.is_ascii_alphanumeric()) { pool += 33; }
        if password.chars().any(|c| !c.is_ascii()) { pool += 1000; }
        (pool > 0).then_some(pool)
    }

    /// Expected seconds to find the password by exhaustive search at
    /// `guesses_per_second` (half the key space on average). With `quantum`
    /// the search is modelled as Grover's algorithm: √(key space) queries.
    pub fn crack_time(entropy_bits: f64, guesses_per_second: f64, quantum: bool) -> f64 {
        let bits = if quantum { entropy_bits / 2.0 } else { entropy_bits - 1.0 };
        2f64.powf(bits.max(0.0)) / guesses_per_second
    }

    /// 1-based rank in the top-1000 list, or 0 if absent.
    pub fn common_password_rank(password: &str) -> u32 {
        TOP_1000.lines().position(|l| l == password).map(|i| i as u32 + 1).unwrap_or(0)
    }

    /// PBKDF2-HMAC-SHA256 (RFC 8018 §5.2); returns `len` bytes as hex.
    pub fn pbkdf2_sha256(password: &str, salt: &[u8], iterations: u32, len: u32) -> Result<String> {
        if iterations == 0 { return Err(CryptoError::new("Iterations must be ≥ 1")); }
        let mut out = vec![0u8; len.clamp(1, 64) as usize];
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut out);
        Ok(hex::encode(out))
    }

    /// Argon2id v1.3 with memory `m_kib` KiB, `t` passes and `p` lanes; 32-byte tag as hex.
    pub fn argon2id(password: &str, salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<String> {
        let params = ParamsBuilder::new().m_cost(m_kib).t_cost(t).p_cost(p).output_len(32).build()
            .map_err(|e| CryptoError::new(format!("Argon2 parameters: {e}")))?;
        let mut out = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password.as_bytes(), salt, &mut out)
            .map_err(|e| CryptoError::new(format!("Argon2: {e}")))?;
        Ok(hex::encode(out))
    }

    /// Chains `iterations` SHA-256 computations (each input is the previous
    /// digest) and returns the final digest. Timing is done by the caller.
    pub fn benchmark_sha256(iterations: u32) -> String {
        let mut data = [0u8; 32];
        for _ in 0..iterations {
            data = Sha256::digest(data).into();
        }
        hex::encode(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_model() {
        assert_eq!(PasswordSecurity::calculate_entropy(""), 0.0);
        assert!((PasswordSecurity::calculate_entropy("aaaaaaaa") - 8.0 * 26f64.log2()).abs() < 1e-9);
        assert_eq!(PasswordSecurity::alphabet_size("aA1!"), Some(95));
        assert!(PasswordSecurity::crack_time(40.0, 1e10, false) < PasswordSecurity::crack_time(41.0, 1e10, false));
        assert!(PasswordSecurity::crack_time(64.0, 1.0, true) < PasswordSecurity::crack_time(64.0, 1.0, false));
    }

    #[test]
    fn wordlist_is_embedded_and_ranked() {
        assert_eq!(TOP_1000.lines().count(), 1000);
        assert_eq!(PasswordSecurity::common_password_rank("123456"), 1);
        assert_eq!(PasswordSecurity::common_password_rank("password"), 2);
        assert_eq!(PasswordSecurity::common_password_rank("correct horse battery staple"), 0);
    }

    #[test]
    fn pbkdf2_sha256_known_answers() {
        assert_eq!(PasswordSecurity::pbkdf2_sha256("password", b"salt", 1, 32).unwrap(), "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
        assert_eq!(PasswordSecurity::pbkdf2_sha256("password", b"salt", 2, 32).unwrap(), "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
        assert_eq!(PasswordSecurity::pbkdf2_sha256("password", b"salt", 4096, 32).unwrap(), "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
        assert!(PasswordSecurity::pbkdf2_sha256("x", b"s", 0, 32).is_err());
    }

    #[test]
    fn argon2id_is_deterministic_and_salted() {
        let a = PasswordSecurity::argon2id("password", b"somesalt", 64, 2, 1).unwrap();
        let b = PasswordSecurity::argon2id("password", b"somesalt", 64, 2, 1).unwrap();
        let c = PasswordSecurity::argon2id("password", b"othersalt", 64, 2, 1).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
        assert!(PasswordSecurity::argon2id("x", b"salt", 1, 1, 0).is_err());
    }

    #[test]
    fn argon2id_rfc_9106_vector() {
        // RFC 9106 §5.3 uses a secret and associated data; reproduce it with
        // the underlying API to prove the crate is wired to the right variant.
        let ad = argon2::AssociatedData::new(&[4u8; 12]).unwrap();
        let params = ParamsBuilder::new().m_cost(32).t_cost(3).p_cost(4).data(ad).output_len(32).build().unwrap();
        let a = Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out).unwrap();
        assert_eq!(hex::encode(out), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    }
}
