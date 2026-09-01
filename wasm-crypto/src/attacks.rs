//! Two active attacks, run end to end so their mechanics can be watched:
//! the CBC padding-oracle attack (Vaudenay, 2002) and a man-in-the-middle on
//! unauthenticated Diffie–Hellman.
//!
//! Both are the reason for a defence elsewhere on the site — AEAD in §2, and
//! certificates/signatures in §8 — so each attack returns enough of a trace to
//! show *why* the countermeasure exists.

use crate::block_ciphers::{aes_mode_raw, pkcs7_pad, pkcs7_unpad};
use crate::{CryptoError, Result};
use num_bigint::BigUint;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/* Padding oracle ------------------------------------------------------------ */

#[derive(Serialize)]
pub struct PaddingOracleAttack {
    pub key: String,
    pub iv: String,
    pub ciphertext: String,
    pub recovered_hex: String,
    pub recovered_text: String,
    pub matched: bool,
    pub oracle_calls: u32,
    pub blocks_attacked: u32,
}

/// The oracle the server unwittingly provides: decrypt (iv ‖ ct) and report
/// only whether the PKCS#7 padding was valid. This is the single bit of
/// feedback the attack needs; it never sees the plaintext or the key.
fn padding_is_valid(key: &[u8], iv: &[u8; 16], ct: &[u8]) -> bool {
    match aes_mode_raw("cbc", key, iv, ct, false) {
        Ok(pt) => pkcs7_unpad(pt).is_ok(),
        Err(_) => false,
    }
}

/// Recovers the *intermediate* state D_K(target) of one ciphertext block using
/// only the oracle. XORing the result with the block's CBC predecessor gives
/// the plaintext; the caller does that, since the attack itself never needs the
/// predecessor — the forged block plays that role during the search.
fn recover_intermediate(key: &[u8], target: &[u8; 16], calls: &mut u32) -> Result<[u8; 16]> {
    let mut inter = [0u8; 16];
    for pad in 1u8..=16 {
        let i = 16 - pad as usize;
        // Forge the preceding block so the already-known tail decrypts to the
        // padding value `pad`, then search the unknown byte.
        let mut forged = [0u8; 16];
        for j in (i + 1)..16 {
            forged[j] = inter[j] ^ pad;
        }
        let mut found = false;
        for guess in 0u16..=255 {
            forged[i] = guess as u8;
            *calls += 1;
            // The oracle takes an IV plus one block; here the forged block is
            // the IV and `target` is the single ciphertext block.
            if padding_is_valid(key, &forged, target) {
                // Guard against the false positive where a longer real padding
                // happened to be valid: perturb the byte before and re-check.
                if pad == 1 {
                    forged[i - 1] ^= 0xff;
                    *calls += 1;
                    let still = padding_is_valid(key, &forged, target);
                    forged[i - 1] ^= 0xff;
                    if !still { continue; }
                }
                inter[i] = forged[i] ^ pad;
                found = true;
                break;
            }
        }
        if !found {
            return Err(CryptoError::new("Oracle gave no valid padding for a byte (unexpected)"));
        }
    }
    Ok(inter)
}

/// Encrypts `plaintext` under a fresh random key, then recovers it back using
/// only the padding oracle — never the key. Proof that a server which leaks
/// "bad padding" as distinct from "bad MAC" hands over its plaintext.
pub fn run_padding_oracle(plaintext: &[u8]) -> Result<PaddingOracleAttack> {
    if plaintext.is_empty() || plaintext.len() > 64 {
        return Err(CryptoError::new("Message must be 1–64 bytes for the demonstration"));
    }
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut iv);
    let ct = aes_mode_raw("cbc", &key, &iv, &pkcs7_pad(plaintext.to_vec()), true)?;

    // Blocks in order, with the IV in front so each has its CBC predecessor.
    let mut blocks: Vec<[u8; 16]> = Vec::new();
    blocks.push(iv);
    for chunk in ct.chunks_exact(16) {
        blocks.push(chunk.try_into().unwrap());
    }

    let mut calls = 0u32;
    let mut recovered = Vec::new();
    for w in blocks.windows(2) {
        let inter = recover_intermediate(&key, &w[1], &mut calls)?;
        for i in 0..16 {
            recovered.push(inter[i] ^ w[0][i]);
        }
    }
    let recovered = pkcs7_unpad(recovered)?;
    let matched = recovered == plaintext;

    Ok(PaddingOracleAttack {
        key: hex::encode(key),
        iv: hex::encode(iv),
        ciphertext: hex::encode(&ct),
        recovered_hex: hex::encode(&recovered),
        recovered_text: String::from_utf8_lossy(&recovered).into_owned(),
        matched,
        oracle_calls: calls,
        blocks_attacked: (blocks.len() - 1) as u32,
    })
}

/* Diffie–Hellman man-in-the-middle ------------------------------------------ */

#[derive(Serialize)]
pub struct DhMitm {
    pub p: String,
    pub g: String,
    pub alice_private: String,
    pub bob_private: String,
    pub mallory_a: String,
    pub mallory_b: String,
    pub alice_sends: String,
    pub bob_sends: String,
    pub mallory_to_bob: String,
    pub mallory_to_alice: String,
    pub alice_secret: String,
    pub bob_secret: String,
    pub mallory_secret_with_alice: String,
    pub mallory_secret_with_bob: String,
    pub alice_deceived: bool,
    pub bob_deceived: bool,
    pub alice_bob_share_a_key: bool,
}

fn parse(s: &str, what: &str) -> Result<BigUint> {
    BigUint::parse_bytes(s.trim().as_bytes(), 10).ok_or_else(|| CryptoError::new(format!("{what} is not a base-10 integer")))
}

/// Alice and Bob run finite-field Diffie–Hellman with no authentication, and
/// Mallory sits in the middle substituting her own public values. Each of them
/// ends up sharing a key with Mallory while believing they share it with the
/// other. The maths never fails — that is the whole problem.
pub fn run_dh_mitm(p_str: &str, g_str: &str, a_str: &str, b_str: &str, m1_str: &str, m2_str: &str) -> Result<DhMitm> {
    let p = parse(p_str, "p")?;
    let g = parse(g_str, "g")?;
    if p < BigUint::from(5u32) { return Err(CryptoError::new("Use a prime p ≥ 5")); }
    let a = parse(a_str, "Alice's private a")?;
    let b = parse(b_str, "Bob's private b")?;
    let m1 = parse(m1_str, "Mallory's m₁")?;
    let m2 = parse(m2_str, "Mallory's m₂")?;

    // Honest public values.
    let big_a = g.modpow(&a, &p);        // Alice → (intercepted)
    let big_b = g.modpow(&b, &p);        // Bob   → (intercepted)
    // Mallory's substitutes, one per victim.
    let mal_to_bob = g.modpow(&m1, &p);  // Mallory → Bob, posing as Alice
    let mal_to_alice = g.modpow(&m2, &p); // Mallory → Alice, posing as Bob

    // Each party raises what they *received* to their own secret.
    let alice_secret = mal_to_alice.modpow(&a, &p);   // Alice: (g^m2)^a
    let bob_secret = mal_to_bob.modpow(&b, &p);        // Bob:   (g^m1)^b
    // Mallory reproduces both from the honest values she intercepted.
    let mal_with_alice = big_a.modpow(&m2, &p);        // (g^a)^m2  == Alice's
    let mal_with_bob = big_b.modpow(&m1, &p);          // (g^b)^m1  == Bob's

    Ok(DhMitm {
        p: p.to_str_radix(10),
        g: g.to_str_radix(10),
        alice_private: a.to_str_radix(10),
        bob_private: b.to_str_radix(10),
        mallory_a: m1.to_str_radix(10),
        mallory_b: m2.to_str_radix(10),
        alice_sends: big_a.to_str_radix(10),
        bob_sends: big_b.to_str_radix(10),
        mallory_to_bob: mal_to_bob.to_str_radix(10),
        mallory_to_alice: mal_to_alice.to_str_radix(10),
        alice_secret: alice_secret.to_str_radix(10),
        bob_secret: bob_secret.to_str_radix(10),
        mallory_secret_with_alice: mal_with_alice.to_str_radix(10),
        mallory_secret_with_bob: mal_with_bob.to_str_radix(10),
        alice_deceived: alice_secret == mal_with_alice,
        bob_deceived: bob_secret == mal_with_bob,
        alice_bob_share_a_key: alice_secret == bob_secret,
    })
}

#[wasm_bindgen]
pub struct Attacks;

#[wasm_bindgen]
impl Attacks {
    /// Runs the CBC padding-oracle attack against a fresh encryption of `text`.
    pub fn padding_oracle(text: &str) -> Result<JsValue> {
        serde_wasm_bindgen::to_value(&run_padding_oracle(text.as_bytes())?).map_err(|e| CryptoError::new(e.to_string()))
    }

    /// Runs a man-in-the-middle on unauthenticated Diffie–Hellman.
    pub fn dh_mitm(p: &str, g: &str, a: &str, b: &str, m1: &str, m2: &str) -> Result<JsValue> {
        serde_wasm_bindgen::to_value(&run_dh_mitm(p, g, a, b, m1, m2)?).map_err(|e| CryptoError::new(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_oracle_recovers_plaintext_without_the_key() {
        for msg in ["hi", "attack at dawn", "the quick brown fox jumped", "0123456789abcdef"] {
            let r = run_padding_oracle(msg.as_bytes()).unwrap();
            assert!(r.matched, "failed on {msg:?}");
            assert_eq!(r.recovered_text, msg);
            // Every block takes at most 256 tries per byte; far fewer than brute force.
            assert!(r.oracle_calls > 0);
            assert!(r.oracle_calls < r.blocks_attacked * 16 * 300);
        }
        assert!(run_padding_oracle(b"").is_err());
    }

    #[test]
    fn dh_mitm_gives_mallory_both_keys() {
        // The RFC 3526-style small example p = 23, g = 5.
        let r = run_dh_mitm("23", "5", "6", "15", "3", "7").unwrap();
        assert!(r.alice_deceived, "Alice must share her key with Mallory");
        assert!(r.bob_deceived, "Bob must share his key with Mallory");
        // The victims never agree on a key with each other.
        assert!(!r.alice_bob_share_a_key);
        assert_eq!(r.alice_secret, r.mallory_secret_with_alice);
        assert_eq!(r.bob_secret, r.mallory_secret_with_bob);
        // Larger honest parameters behave the same way.
        let big = run_dh_mitm("2147483647", "7", "123456", "654321", "111", "222").unwrap();
        assert!(big.alice_deceived && big.bob_deceived);
        assert!(run_dh_mitm("4", "2", "1", "1", "1", "1").is_err());
    }
}
