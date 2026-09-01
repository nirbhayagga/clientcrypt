//! Public-key cryptography: RSA (RFC 8017), finite-field Diffie–Hellman
//! with the RFC 7919 groups, and X25519 (RFC 7748).

use crate::{CryptoError, Result};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

/* RFC 7919 finite-field groups (Appendix A). Generator g = 2 for all. */
const FFDHE2048: &[&str] = &[
    "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695",
    "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a",
    "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935",
    "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a",
    "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4",
    "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61",
    "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005",
    "c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff",
];
const FFDHE3072: &[&str] = &[
    "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695",
    "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a",
    "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935",
    "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a",
    "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4",
    "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61",
    "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005",
    "c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b",
    "bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c",
    "aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff",
    "5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e",
    "0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b66c62e37ffffffffffffffff",
];
const FFDHE4096: &[&str] = &[
    "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695",
    "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a",
    "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935",
    "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a",
    "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4",
    "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61",
    "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005",
    "c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b",
    "bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c",
    "aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff",
    "5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e",
    "0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb",
    "7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a",
    "7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038",
    "092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf",
    "8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e655f6affffffffffffffff",
];

#[derive(Serialize)]
pub struct Group {
    pub name: String,
    pub bits: u32,
    pub p_hex: String,
    pub g_hex: String,
    pub safe_prime: bool,
}

#[derive(Serialize)]
pub struct RsaComponents {
    pub bits: u32,
    pub n: String,
    pub e: String,
    pub d: String,
    pub p: String,
    pub q: String,
}

fn parse_hex(s: &str, what: &str) -> Result<BigUint> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() { return Err(CryptoError::new(format!("{what} is empty"))); }
    BigUint::parse_bytes(clean.as_bytes(), 16).ok_or_else(|| CryptoError::new(format!("{what} is not valid hex")))
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(|e| CryptoError::new(e.to_string()))
}

fn rsa_err(e: rsa::Error) -> CryptoError { CryptoError::new(format!("RSA: {e}")) }

fn priv_key(pem: &str) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs1_pem(pem).map_err(|_| CryptoError::new("Private key is not a valid PKCS#1 PEM"))
}

fn pub_key(pem: &str) -> Result<RsaPublicKey> {
    RsaPublicKey::from_pkcs1_pem(pem).map_err(|_| CryptoError::new("Public key is not a valid PKCS#1 PEM"))
}

/* Miller–Rabin --------------------------------------------------------------- */

const SMALL_PRIMES: [u32; 25] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97];

/// Probabilistic primality test; error probability ≤ 4^-rounds for composites.
pub fn is_probable_prime(n: &BigUint, rounds: u32) -> bool {
    if n < &BigUint::from(2u32) { return false; }
    for &sp in &SMALL_PRIMES {
        let spb = BigUint::from(sp);
        if n == &spb { return true; }
        if (n % &spb).is_zero() { return false; }
    }
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let n_minus_1 = n - &one;
    let s = n_minus_1.trailing_zeros().unwrap_or(0);
    let d = &n_minus_1 >> s;
    let mut rng = OsRng;
    'witness: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&two, &n_minus_1);
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 { continue; }
        for _ in 1..s {
            x = x.modpow(&two, n);
            if x == n_minus_1 { continue 'witness; }
        }
        return false;
    }
    true
}

/// Random safe prime p = 2q + 1 with q prime, of exactly `bits` bits.
pub fn generate_safe_prime(bits: u64) -> BigUint {
    let mut rng = OsRng;
    loop {
        let mut q = rng.gen_biguint(bits - 1);
        q.set_bit(bits - 2, true);
        q.set_bit(0, true);
        if !is_probable_prime(&q, 8) { continue; }
        let p = (&q << 1u32) + BigUint::one();
        if is_probable_prime(&p, 16) { return p; }
    }
}

#[wasm_bindgen]
pub struct AsymmetricCrypto;

#[wasm_bindgen]
impl AsymmetricCrypto {
    /* RSA ---------------------------------------------------------------- */

    /// Generates an RSA key pair; returns [private PEM, public PEM] (PKCS#1).
    pub fn rsa_generate_keys(bits: u32) -> Result<Vec<String>> {
        if !(1024..=4096).contains(&bits) { return Err(CryptoError::new("Key size must be between 1024 and 4096 bits")); }
        let key = RsaPrivateKey::new(&mut OsRng, bits as usize).map_err(rsa_err)?;
        let pubkey = RsaPublicKey::from(&key);
        Ok(vec![
            key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).map_err(|e| CryptoError::new(e.to_string()))?.to_string(),
            pubkey.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).map_err(|e| CryptoError::new(e.to_string()))?,
        ])
    }

    /// The integers behind a private key: n, e, d, p, q (hex).
    pub fn rsa_key_components(priv_pem: &str) -> Result<JsValue> {
        let key = priv_key(priv_pem)?;
        let primes = key.primes();
        to_js(&RsaComponents {
            bits: key.size() as u32 * 8,
            n: key.n().to_str_radix(16),
            e: key.e().to_str_radix(16),
            d: key.d().to_str_radix(16),
            p: primes.first().map(|p| p.to_str_radix(16)).unwrap_or_default(),
            q: primes.get(1).map(|q| q.to_str_radix(16)).unwrap_or_default(),
        })
    }

    /// Largest message (bytes) the scheme can encrypt under this key.
    pub fn rsa_max_message_len(pub_pem: &str, scheme: &str) -> Result<u32> {
        let k = pub_key(pub_pem)?.size() as i64;
        let n = match scheme { "pkcs1v15" => k - 11, "oaep-sha256" => k - 2 * 32 - 2, _ => return Err(CryptoError::new("Scheme must be pkcs1v15 or oaep-sha256")) };
        Ok(n.max(0) as u32)
    }

    /// Encrypts `data` with the public key; scheme: "pkcs1v15" or "oaep-sha256".
    pub fn rsa_encrypt(pub_pem: &str, scheme: &str, data: &[u8]) -> Result<String> {
        let key = pub_key(pub_pem)?;
        let ct = match scheme {
            "pkcs1v15" => key.encrypt(&mut OsRng, Pkcs1v15Encrypt, data),
            "oaep-sha256" => key.encrypt(&mut OsRng, Oaep::new::<Sha256>(), data),
            _ => return Err(CryptoError::new("Scheme must be pkcs1v15 or oaep-sha256")),
        }.map_err(rsa_err)?;
        Ok(hex::encode(ct))
    }

    pub fn rsa_decrypt(priv_pem: &str, scheme: &str, ct_hex: &str) -> Result<Vec<u8>> {
        let key = priv_key(priv_pem)?;
        let ct = hex::decode(ct_hex)?;
        match scheme {
            "pkcs1v15" => key.decrypt(Pkcs1v15Encrypt, &ct),
            "oaep-sha256" => key.decrypt(Oaep::new::<Sha256>(), &ct),
            _ => return Err(CryptoError::new("Scheme must be pkcs1v15 or oaep-sha256")),
        }.map_err(rsa_err)
    }

    /// Signs `msg`; scheme: "pkcs1v15-sha256" or "pss-sha256". Returns hex.
    pub fn rsa_sign(priv_pem: &str, scheme: &str, msg: &[u8]) -> Result<String> {
        let key = priv_key(priv_pem)?;
        let sig = match scheme {
            "pkcs1v15-sha256" => rsa::pkcs1v15::SigningKey::<Sha256>::new(key).sign(msg).to_vec(),
            "pss-sha256" => rsa::pss::SigningKey::<Sha256>::new(key).sign_with_rng(&mut OsRng, msg).to_vec(),
            _ => return Err(CryptoError::new("Scheme must be pkcs1v15-sha256 or pss-sha256")),
        };
        Ok(hex::encode(sig))
    }

    /// Verifies a signature; returns false (not an error) for a bad signature.
    pub fn rsa_verify(pub_pem: &str, scheme: &str, msg: &[u8], sig_hex: &str) -> Result<bool> {
        let key = pub_key(pub_pem)?;
        let sig = hex::decode(sig_hex)?;
        Ok(match scheme {
            "pkcs1v15-sha256" => rsa::pkcs1v15::Signature::try_from(sig.as_slice())
                .map(|s| rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key).verify(msg, &s).is_ok()).unwrap_or(false),
            "pss-sha256" => rsa::pss::Signature::try_from(sig.as_slice())
                .map(|s| rsa::pss::VerifyingKey::<Sha256>::new(key).verify(msg, &s).is_ok()).unwrap_or(false),
            _ => return Err(CryptoError::new("Scheme must be pkcs1v15-sha256 or pss-sha256")),
        })
    }

    /* Finite-field Diffie–Hellman ---------------------------------------- */

    /// A standardised group: "ffdhe2048", "ffdhe3072" or "ffdhe4096".
    pub fn dh_group(name: &str) -> Result<JsValue> {
        let (bits, parts): (u32, &[&str]) = match name {
            "ffdhe2048" => (2048, FFDHE2048),
            "ffdhe3072" => (3072, FFDHE3072),
            "ffdhe4096" => (4096, FFDHE4096),
            _ => return Err(CryptoError::new("Unknown group (ffdhe2048, ffdhe3072, ffdhe4096)")),
        };
        to_js(&Group { name: name.to_string(), bits, p_hex: parts.concat(), g_hex: "2".into(), safe_prime: true })
    }

    /// Generates a fresh safe prime of `bits` bits (64–512) with g = 2.
    /// Demonstration only — far too small for real use.
    pub fn dh_generate_group(bits: u32) -> Result<JsValue> {
        if !(64..=512).contains(&bits) { return Err(CryptoError::new("Bits must be between 64 and 512")); }
        let p = generate_safe_prime(bits as u64);
        to_js(&Group { name: format!("random {bits}-bit safe prime"), bits, p_hex: p.to_str_radix(16), g_hex: "2".into(), safe_prime: true })
    }

    /// Miller–Rabin check of a hex integer (16 rounds).
    pub fn is_probable_prime_hex(n_hex: &str) -> Result<bool> {
        Ok(is_probable_prime(&parse_hex(n_hex, "n")?, 16))
    }

    /// Random private exponent in [2, p − 2].
    pub fn dh_private(p_hex: &str) -> Result<String> {
        let p = parse_hex(p_hex, "p")?;
        if p < BigUint::from(5u32) { return Err(CryptoError::new("p is too small")); }
        let two = BigUint::from(2u32);
        Ok(OsRng.gen_biguint_range(&two, &(&p - &two)).to_str_radix(16))
    }

    /// g^x mod p.
    pub fn dh_public(p_hex: &str, g_hex: &str, x_hex: &str) -> Result<String> {
        let p = parse_hex(p_hex, "p")?;
        let g = parse_hex(g_hex, "g")?;
        let x = parse_hex(x_hex, "private exponent")?;
        if x.is_zero() { return Err(CryptoError::new("Private exponent must be non-zero")); }
        Ok(g.modpow(&x, &p).to_str_radix(16))
    }

    /// Y^x mod p, after checking 2 ≤ Y ≤ p − 2 (rejects the degenerate values
    /// 0, 1 and p − 1 an attacker could send to force a known secret).
    pub fn dh_shared(p_hex: &str, their_pub_hex: &str, x_hex: &str) -> Result<String> {
        let p = parse_hex(p_hex, "p")?;
        let y = parse_hex(their_pub_hex, "peer public value")?;
        let x = parse_hex(x_hex, "private exponent")?;
        let two = BigUint::from(2u32);
        if y < two || y > &p - &two { return Err(CryptoError::new("Peer public value out of range [2, p − 2]")); }
        Ok(y.modpow(&x, &p).to_str_radix(16))
    }

    /* Ed25519 ----------------------------------------------------------- */

    /// Returns [private, public] as 32-byte hex strings. Ed25519 keys are the
    /// same curve as X25519 but a different encoding, and must never be reused
    /// across the two: signing and key agreement have different security
    /// arguments.
    pub fn ed25519_keypair() -> Vec<String> {
        let mut sk = [0u8; 32];
        OsRng.fill_bytes(&mut sk);
        let signing = ed25519_dalek::SigningKey::from_bytes(&sk);
        vec![hex::encode(signing.to_bytes()), hex::encode(signing.verifying_key().to_bytes())]
    }

    /// Public key for a 32-byte Ed25519 seed.
    pub fn ed25519_public(priv_hex: &str) -> Result<String> {
        let sk: [u8; 32] = hex::decode(priv_hex)?.try_into().map_err(|_| CryptoError::new("Private key must be 32 bytes"))?;
        Ok(hex::encode(ed25519_dalek::SigningKey::from_bytes(&sk).verifying_key().to_bytes()))
    }

    /// Signs `msg`; the 64-byte signature is deterministic (RFC 8032), so the
    /// same key and message always give the same signature — no nonce to leak.
    pub fn ed25519_sign(priv_hex: &str, msg: &[u8]) -> Result<String> {
        use ed25519_dalek::Signer;
        let sk: [u8; 32] = hex::decode(priv_hex)?.try_into().map_err(|_| CryptoError::new("Private key must be 32 bytes"))?;
        Ok(hex::encode(ed25519_dalek::SigningKey::from_bytes(&sk).sign(msg).to_bytes()))
    }

    /// Verifies a signature; a bad signature is `false`, not an error.
    pub fn ed25519_verify(pub_hex: &str, msg: &[u8], sig_hex: &str) -> Result<bool> {
        use ed25519_dalek::Verifier;
        let pk: [u8; 32] = hex::decode(pub_hex)?.try_into().map_err(|_| CryptoError::new("Public key must be 32 bytes"))?;
        let key = match ed25519_dalek::VerifyingKey::from_bytes(&pk) {
            Ok(k) => k,
            Err(_) => return Ok(false),
        };
        let sig_bytes = hex::decode(sig_hex)?;
        let sig: [u8; 64] = match sig_bytes.try_into() {
            Ok(b) => b,
            Err(_) => return Ok(false),
        };
        Ok(key.verify(msg, &ed25519_dalek::Signature::from_bytes(&sig)).is_ok())
    }

    /* X25519 ------------------------------------------------------------ */

    /// Returns [private, public] as 32-byte hex strings.
    pub fn x25519_keypair() -> Vec<String> {
        let mut sk = [0u8; 32];
        OsRng.fill_bytes(&mut sk);
        let secret = x25519_dalek::StaticSecret::from(sk);
        let public = x25519_dalek::PublicKey::from(&secret);
        vec![hex::encode(secret.to_bytes()), hex::encode(public.as_bytes())]
    }

    /// Public key for a given 32-byte private scalar (clamped per RFC 7748).
    pub fn x25519_public(priv_hex: &str) -> Result<String> {
        let sk: [u8; 32] = hex::decode(priv_hex)?.try_into().map_err(|_| CryptoError::new("Private key must be 32 bytes"))?;
        Ok(hex::encode(x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(sk)).as_bytes()))
    }

    /// X25519(k, u): the shared secret. Rejects the all-zero output produced
    /// by low-order points, as RFC 7748 §6.1 recommends.
    pub fn x25519_shared(priv_hex: &str, their_pub_hex: &str) -> Result<String> {
        let sk: [u8; 32] = hex::decode(priv_hex)?.try_into().map_err(|_| CryptoError::new("Private key must be 32 bytes"))?;
        let pk: [u8; 32] = hex::decode(their_pub_hex)?.try_into().map_err(|_| CryptoError::new("Public key must be 32 bytes"))?;
        let shared = x25519_dalek::StaticSecret::from(sk).diffie_hellman(&x25519_dalek::PublicKey::from(pk));
        if !shared.was_contributory() { return Err(CryptoError::new("Peer public key is a low-order point")); }
        Ok(hex::encode(shared.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_encrypt_sign_roundtrip() {
        // OAEP-SHA256 needs k > 66 bytes and PSS-SHA256 k >= 66, so 512-bit keys
        // cannot be used with them; 1024 is the smallest size the UI offers.
        let keys = AsymmetricCrypto::rsa_generate_keys(1024).unwrap();
        let (sk, pk) = (&keys[0], &keys[1]);
        for scheme in ["pkcs1v15", "oaep-sha256"] {
            let ct = AsymmetricCrypto::rsa_encrypt(pk, scheme, b"hello").unwrap();
            assert_eq!(AsymmetricCrypto::rsa_decrypt(sk, scheme, &ct).unwrap(), b"hello");
            let max = AsymmetricCrypto::rsa_max_message_len(pk, scheme).unwrap() as usize;
            assert!(AsymmetricCrypto::rsa_encrypt(pk, scheme, &vec![1u8; max + 1]).is_err());
        }
        for scheme in ["pkcs1v15-sha256", "pss-sha256"] {
            let sig = AsymmetricCrypto::rsa_sign(sk, scheme, b"msg").unwrap();
            assert!(AsymmetricCrypto::rsa_verify(pk, scheme, b"msg", &sig).unwrap());
            assert!(!AsymmetricCrypto::rsa_verify(pk, scheme, b"msh", &sig).unwrap());
            assert!(!AsymmetricCrypto::rsa_verify(pk, scheme, b"msg", "00").unwrap());
        }
        assert!(AsymmetricCrypto::rsa_encrypt("junk", "pkcs1v15", b"x").is_err());
        assert!(AsymmetricCrypto::rsa_generate_keys(100).is_err());
    }

    #[test]
    fn rsa_components_are_consistent() {
        let keys = AsymmetricCrypto::rsa_generate_keys(1024).unwrap();
        let key = priv_key(&keys[0]).unwrap();
        let primes = key.primes();
        assert_eq!(&primes[0] * &primes[1], *key.n());
        assert_eq!(key.e(), &rsa::BigUint::from(65537u32));
    }

    #[test]
    fn ffdhe2048_is_a_safe_prime() {
        let p = BigUint::parse_bytes(FFDHE2048.concat().as_bytes(), 16).unwrap();
        assert_eq!(p.bits(), 2048);
        assert!(is_probable_prime(&p, 4));
        assert!(is_probable_prime(&((&p - BigUint::one()) >> 1u32), 2));
        assert_eq!(FFDHE3072.concat().len() * 4, 3072);
        assert_eq!(FFDHE4096.concat().len() * 4, 4096);
    }

    #[test]
    fn miller_rabin_and_safe_prime_generation() {
        assert!(is_probable_prime(&BigUint::from(2u32), 8));
        assert!(is_probable_prime(&BigUint::from(97u32), 8));
        assert!(is_probable_prime(&BigUint::from(1_000_000_007u32), 8));
        assert!(!is_probable_prime(&BigUint::from(1u32), 8));
        assert!(!is_probable_prime(&BigUint::from(561u32), 8)); // Carmichael number
        assert!(!is_probable_prime(&BigUint::from(1_000_000_007u64 * 3), 8));
        let p = generate_safe_prime(64);
        assert_eq!(p.bits(), 64);
        assert!(is_probable_prime(&p, 16));
        assert!(is_probable_prime(&((&p - BigUint::one()) >> 1u32), 16));
    }

    #[test]
    fn diffie_hellman_agreement_and_validation() {
        let p = generate_safe_prime(96).to_str_radix(16);
        let a = AsymmetricCrypto::dh_private(&p).unwrap();
        let b = AsymmetricCrypto::dh_private(&p).unwrap();
        let big_a = AsymmetricCrypto::dh_public(&p, "2", &a).unwrap();
        let big_b = AsymmetricCrypto::dh_public(&p, "2", &b).unwrap();
        assert_eq!(AsymmetricCrypto::dh_shared(&p, &big_b, &a).unwrap(), AsymmetricCrypto::dh_shared(&p, &big_a, &b).unwrap());
        assert!(AsymmetricCrypto::dh_shared(&p, "1", &a).is_err());
        assert!(AsymmetricCrypto::dh_shared(&p, "0", &a).is_err());
        assert!(AsymmetricCrypto::dh_public(&p, "2", "zz").is_err());
    }

    #[test]
    fn ed25519_rfc_8032_vectors() {
        // RFC 8032 section 7.1, TEST 1 (empty message) and TEST 2 (one byte).
        let cases = [
            ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
             "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
             "",
             "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
              5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
            ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
             "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
             "72",
             "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
              085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ];
        for (sk, pk, msg_hex, sig) in cases {
            let sig: String = sig.chars().filter(|c| !c.is_whitespace()).collect();
            let msg = hex::decode(msg_hex).unwrap();
            assert_eq!(AsymmetricCrypto::ed25519_public(sk).unwrap(), pk);
            assert_eq!(AsymmetricCrypto::ed25519_sign(sk, &msg).unwrap(), sig);
            assert!(AsymmetricCrypto::ed25519_verify(pk, &msg, &sig).unwrap());
            // Signatures are deterministic: signing twice gives the same bytes.
            assert_eq!(AsymmetricCrypto::ed25519_sign(sk, &msg).unwrap(), sig);
            // A changed message must not verify.
            assert!(!AsymmetricCrypto::ed25519_verify(pk, b"different", &sig).unwrap());
        }
        // Malformed input is a false verdict, never a panic.
        assert!(!AsymmetricCrypto::ed25519_verify(&"00".repeat(32), b"m", &"00".repeat(64)).unwrap());
        assert!(!AsymmetricCrypto::ed25519_verify(&"00".repeat(32), b"m", "00").unwrap());
        let pair = AsymmetricCrypto::ed25519_keypair();
        assert_eq!(AsymmetricCrypto::ed25519_public(&pair[0]).unwrap(), pair[1]);
    }

    #[test]
    fn x25519_rfc_7748_vector() {
        let alice_sk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        let bob_sk = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        let alice_pk = AsymmetricCrypto::x25519_public(alice_sk).unwrap();
        let bob_pk = AsymmetricCrypto::x25519_public(bob_sk).unwrap();
        assert_eq!(alice_pk, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(bob_pk, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let k = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assert_eq!(AsymmetricCrypto::x25519_shared(alice_sk, &bob_pk).unwrap(), k);
        assert_eq!(AsymmetricCrypto::x25519_shared(bob_sk, &alice_pk).unwrap(), k);
        assert!(AsymmetricCrypto::x25519_shared(alice_sk, &"00".repeat(32)).is_err());
        let pair = AsymmetricCrypto::x25519_keypair();
        assert_eq!(AsymmetricCrypto::x25519_public(&pair[0]).unwrap(), pair[1]);
    }
}
