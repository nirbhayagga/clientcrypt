//! Password strength estimation and password-based key derivation
//! (PBKDF2, RFC 8018; Argon2id, RFC 9106).

use crate::{CryptoError, Result};
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

/// The 1,000 most common passwords from the xato-net 10-million corpus, via
/// SecLists (MIT). One per line, most common first.
const TOP_1000: &str = include_str!("../data/top-1000-passwords.txt");

/// The EFF long diceware list: 7,776 words (5 dice rolls each), chosen to be
/// easy to type and free of confusable pairs (CC BY 3.0 US).
const EFF_WORDLIST: &str = include_str!("../data/eff-wordlist.txt");

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
        if !password.is_ascii() { pool += 1000; }
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

    /// scrypt (RFC 7914) with cost 2^log_n, block size r and parallelism p;
    /// 32-byte output as hex. Memory use is roughly 128 · r · 2^log_n bytes.
    pub fn scrypt(password: &str, salt: &[u8], log_n: u8, r: u32, p: u32) -> Result<String> {
        let params = scrypt::Params::new(log_n, r, p, 32)
            .map_err(|e| CryptoError::new(format!("scrypt parameters: {e}")))?;
        let mut out = [0u8; 32];
        scrypt::scrypt(password.as_bytes(), salt, &params, &mut out)
            .map_err(|e| CryptoError::new(format!("scrypt: {e}")))?;
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

    /// Generates a diceware passphrase of `words` words, each chosen uniformly
    /// at random from the 7,776-word EFF list using the OS CSPRNG. Every word
    /// contributes exactly log₂(7776) ≈ 12.925 bits, so the entropy is honest
    /// and countable — unlike a "complex" password whose entropy is guessed.
    pub fn diceware(words: u32, separator: &str) -> Result<String> {
        use rand::Rng;
        if !(1..=20).contains(&words) {
            return Err(CryptoError::new("Choose 1–20 words"));
        }
        let list: Vec<&str> = EFF_WORDLIST.lines().collect();
        let mut rng = rand::rngs::OsRng;
        let chosen: Vec<&str> = (0..words).map(|_| list[rng.gen_range(0..list.len())]).collect();
        Ok(chosen.join(separator))
    }

    /// Bits of entropy in a `words`-word diceware passphrase: words · log₂(7776).
    pub fn diceware_entropy(words: u32) -> f64 {
        words as f64 * (7776f64).log2()
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

    /// Runs the embedded top-1000 list against a leaked hash of `target`,
    /// hashing each candidate the same way the "server" did. Returns the
    /// 1-based rank at which `target` was found (0 if it is not in the list)
    /// and how many candidates were tried getting there. The caller times the
    /// call, which is the whole point: a fast hash searches the list in
    /// milliseconds, a memory-hard one takes seconds per guess.
    ///
    /// `alg` is a fast digest ("md5", "sha1", "sha256", "sha512"), "pbkdf2"
    /// (HMAC-SHA256 with `cost` iterations) or "argon2" (`cost` KiB of memory,
    /// one pass). `salt` matches what the defender stored.
    /// `max_candidates` caps the number hashed so a memory-hard function does
    /// not hang the page; the caller sizes it by the hash's speed. Every
    /// candidate up to the cap is hashed (no early exit) so the elapsed time
    /// the caller measures reflects a stable count and yields a real rate.
    pub fn dictionary_attack(alg: &str, cost: u32, salt: &[u8], target: &str, max_candidates: u32) -> Result<DictionaryResult> {
        let want = hash_candidate(alg, cost, salt, target)?;
        let cap = max_candidates.clamp(1, 1000);
        let mut found_rank = 0u32;
        let mut tried = 0u32;
        for (i, candidate) in TOP_1000.lines().take(cap as usize).enumerate() {
            tried += 1;
            if found_rank == 0 && hash_candidate(alg, cost, salt, candidate)? == want {
                found_rank = i as u32 + 1;
            } else {
                // Hash anyway, so the timing covers a fixed amount of work.
                let _ = hash_candidate(alg, cost, salt, candidate)?;
            }
        }
        Ok(DictionaryResult { found_rank, tried, list_size: 1000 })
    }
}

/// One candidate hashed the way the defender would have stored it.
fn hash_candidate(alg: &str, cost: u32, salt: &[u8], candidate: &str) -> Result<Vec<u8>> {
    match alg {
        "md5" | "sha1" | "sha256" | "sha512" => {
            // Salted fast hash: what an unwise site actually does.
            let mut input = salt.to_vec();
            input.extend_from_slice(candidate.as_bytes());
            crate::hashing::digest_bytes(alg, &input)
        }
        "pbkdf2" => {
            let mut out = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(candidate.as_bytes(), salt, cost.max(1), &mut out);
            Ok(out.to_vec())
        }
        "argon2" => {
            if salt.len() < 8 { return Err(CryptoError::new("Argon2 needs a salt of at least 8 bytes")); }
            let params = ParamsBuilder::new().m_cost(cost.max(8)).t_cost(1).p_cost(1).output_len(32).build()
                .map_err(|e| CryptoError::new(format!("Argon2 parameters: {e}")))?;
            let mut out = [0u8; 32];
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(candidate.as_bytes(), salt, &mut out)
                .map_err(|e| CryptoError::new(format!("Argon2: {e}")))?;
            Ok(out.to_vec())
        }
        other => Err(CryptoError::new(format!("Unknown algorithm '{other}'"))),
    }
}

/// Outcome of a dictionary attack, serialised to JS.
#[wasm_bindgen]
pub struct DictionaryResult {
    found_rank: u32,
    tried: u32,
    list_size: u32,
}

#[wasm_bindgen]
impl DictionaryResult {
    #[wasm_bindgen(getter)]
    pub fn found_rank(&self) -> u32 { self.found_rank }
    #[wasm_bindgen(getter)]
    pub fn tried(&self) -> u32 { self.tried }
    #[wasm_bindgen(getter)]
    pub fn list_size(&self) -> u32 { self.list_size }
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
    fn diceware_wordlist_and_generation() {
        assert_eq!(EFF_WORDLIST.lines().count(), 7776);
        // Six words is the classic recommendation: ~77.5 bits.
        assert!((PasswordSecurity::diceware_entropy(6) - 77.5).abs() < 0.1);
        let phrase = PasswordSecurity::diceware(6, "-").unwrap();
        assert_eq!(phrase.split('-').count(), 6);
        // Every word must come from the list.
        let list: std::collections::HashSet<&str> = EFF_WORDLIST.lines().collect();
        assert!(phrase.split('-').all(|w| list.contains(w)));
        assert!(PasswordSecurity::diceware(0, "-").is_err());
        assert!(PasswordSecurity::diceware(21, "-").is_err());
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
    fn dictionary_attack_finds_common_passwords_by_rank() {
        // "password" is #2 in the list; a fast salted hash finds it there.
        let r = PasswordSecurity::dictionary_attack("sha256", 0, b"salt", "password", 1000).unwrap();
        assert_eq!(r.found_rank, 2);
        assert_eq!(r.tried, 1000);
        // "123456" is #1.
        assert_eq!(PasswordSecurity::dictionary_attack("md5", 0, b"salt", "123456", 1000).unwrap().found_rank, 1);
        // A password not in the list is searched to exhaustion and not found.
        let miss = PasswordSecurity::dictionary_attack("sha256", 0, b"salt", "correct horse battery staple", 1000).unwrap();
        assert_eq!(miss.found_rank, 0);
        assert_eq!(miss.tried, 1000);
        // The slow hashes locate the same word, just far more expensively per guess.
        assert_eq!(PasswordSecurity::dictionary_attack("pbkdf2", 1000, b"salt", "password", 64).unwrap().found_rank, 2);
        assert_eq!(PasswordSecurity::dictionary_attack("argon2", 512, b"longsalt", "password", 32).unwrap().found_rank, 2);
        assert!(PasswordSecurity::dictionary_attack("crc32", 0, b"salt", "x", 10).is_err());
    }

    #[test]
    fn scrypt_rfc_7914_vector() {
        // RFC 7914 §12: scrypt("password", "NaCl", N=1024, r=8, p=16) — first
        // 32 bytes of the 64-byte output.
        assert_eq!(PasswordSecurity::scrypt("password", b"NaCl", 10, 8, 16).unwrap(),
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162");
        // Cost really is a parameter: a bigger N changes the output.
        let a = PasswordSecurity::scrypt("password", b"NaCl", 8, 8, 1).unwrap();
        let b = PasswordSecurity::scrypt("password", b"NaCl", 9, 8, 1).unwrap();
        assert_ne!(a, b);
        assert!(PasswordSecurity::scrypt("x", b"s", 70, 8, 1).is_err());
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
