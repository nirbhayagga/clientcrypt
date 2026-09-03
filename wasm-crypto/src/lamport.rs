//! Lamport one-time signatures: signing with nothing but a hash function.
//!
//! For every bit of the message digest the signer prepares two random secrets
//! and publishes their hashes; a signature reveals, per bit, the secret on
//! that bit's side. Security is exactly preimage resistance — no number
//! theory, which is why hash-based schemes (SPHINCS+, the standardised
//! ML-DSA alternative) survive a quantum computer. The catch is in the name:
//! sign TWO messages with one key and the revealed halves combine into
//! forgeries, demonstrated below.
//!
//! Toy-sized here: signatures cover the first 16 bits of SHA-256(message) so
//! every value fits on screen. Real Lamport uses all 256 bits.

use crate::{CryptoError, Result};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

pub const BITS: usize = 16;

fn h(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The first BITS bits of SHA-256(msg), most significant first.
fn digest_bits(msg: &str) -> Vec<u8> {
    let d = h(msg.as_bytes());
    (0..BITS).map(|i| (d[i / 8] >> (7 - i % 8)) & 1).collect()
}

fn decode32(s: &str) -> Result<[u8; 32]> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok())
        .ok_or_else(|| CryptoError::new("Expected a 32-byte hex value"))
}

#[derive(Serialize)]
pub struct LamportKey {
    /// secret[i] = [sk_i0, sk_i1] (hex) — kept by the signer.
    pub secret: Vec<[String; 2]>,
    /// public[i] = [H(sk_i0), H(sk_i1)] (hex) — published.
    pub public: Vec<[String; 2]>,
}

pub fn lamport_keygen() -> LamportKey {
    let mut secret = Vec::with_capacity(BITS);
    let mut public = Vec::with_capacity(BITS);
    for _ in 0..BITS {
        let mut s0 = [0u8; 32];
        let mut s1 = [0u8; 32];
        OsRng.fill_bytes(&mut s0);
        OsRng.fill_bytes(&mut s1);
        public.push([hex::encode(h(&s0)), hex::encode(h(&s1))]);
        secret.push([hex::encode(s0), hex::encode(s1)]);
    }
    LamportKey { secret, public }
}

#[derive(Serialize)]
pub struct LamportSignature {
    pub message: String,
    pub bits: Vec<u8>,
    /// Per bit, the revealed secret from the chosen side (hex).
    pub reveal: Vec<String>,
}

/// `secret` is the flattened secret key: 2·BITS hex values, [sk_00, sk_01, sk_10, …].
pub fn lamport_sign(secret: &[String], msg: &str) -> Result<LamportSignature> {
    if secret.len() != 2 * BITS {
        return Err(CryptoError::new(format!("The secret key has 2×{BITS} values")));
    }
    let bits = digest_bits(msg);
    let reveal = bits.iter().enumerate()
        .map(|(i, &b)| secret[2 * i + b as usize].clone())
        .collect();
    Ok(LamportSignature { message: msg.to_string(), bits, reveal })
}

#[derive(Serialize)]
pub struct LamportVerify {
    pub bits: Vec<u8>,
    /// Per bit: does H(revealed secret) equal the published hash on that side?
    pub bit_ok: Vec<bool>,
    pub verified: bool,
}

/// `public` is the flattened public key: 2·BITS hex values.
pub fn lamport_verify(public: &[String], msg: &str, reveal: &[String]) -> Result<LamportVerify> {
    if public.len() != 2 * BITS || reveal.len() != BITS {
        return Err(CryptoError::new(format!("Need 2×{BITS} public hashes and {BITS} revealed secrets")));
    }
    let bits = digest_bits(msg);
    let mut bit_ok = Vec::with_capacity(BITS);
    for (i, &b) in bits.iter().enumerate() {
        let revealed = decode32(&reveal[i])?;
        bit_ok.push(hex::encode(h(&revealed)) == public[2 * i + b as usize]);
    }
    Ok(LamportVerify { verified: bit_ok.iter().all(|&x| x), bits, bit_ok })
}

#[derive(Serialize)]
pub struct LamportForgery {
    /// Bit positions where the two signatures revealed different sides — the
    /// attacker now holds BOTH secrets there.
    pub free_positions: Vec<u32>,
    /// Of the 2^BITS possible digests, how many the attacker can now sign.
    pub forgeable_digests: f64,
    pub forged_message: Option<String>,
    pub forged_reveal: Vec<String>,
    pub attempts: u32,
    pub verified: bool,
}

/// The one-time rule broken: given signatures on two messages under one key,
/// search for a message with the attacker's prefix whose digest only uses
/// revealed secrets, and sign it without the key.
pub fn lamport_forge(msg1: &str, reveal1: &[String], msg2: &str, reveal2: &[String], attacker_prefix: &str) -> Result<LamportForgery> {
    if reveal1.len() != BITS || reveal2.len() != BITS {
        return Err(CryptoError::new(format!("Each signature reveals {BITS} secrets")));
    }
    let b1 = digest_bits(msg1);
    let b2 = digest_bits(msg2);
    let free: Vec<u32> = (0..BITS).filter(|&i| b1[i] != b2[i]).map(|i| i as u32).collect();
    let fixed = BITS - free.len();
    // Positions where both messages agree pin that bit; free positions accept either.
    let forgeable = 2f64.powi(free.len() as i32);

    let mut forged_message = None;
    let mut forged_reveal = Vec::new();
    let mut attempts = 0u32;
    'search: for counter in 0..200_000u32 {
        let candidate = format!("{attacker_prefix}{counter}");
        if candidate == msg1 || candidate == msg2 { continue; }
        attempts = counter + 1;
        let bits = digest_bits(&candidate);
        for i in 0..BITS {
            if bits[i] != b1[i] && bits[i] != b2[i] { continue 'search; }
        }
        forged_reveal = (0..BITS)
            .map(|i| if bits[i] == b1[i] { reveal1[i].clone() } else { reveal2[i].clone() })
            .collect();
        forged_message = Some(candidate);
        break;
    }
    let _ = fixed;
    Ok(LamportForgery {
        free_positions: free,
        forgeable_digests: forgeable,
        verified: forged_message.is_some(),
        forged_message,
        forged_reveal,
        attempts,
    })
}

#[wasm_bindgen]
pub struct Lamport;

#[wasm_bindgen]
impl Lamport {
    pub fn keygen() -> Result<JsValue> {
        to_js(&lamport_keygen())
    }
    pub fn sign(secret: Vec<String>, msg: &str) -> Result<JsValue> {
        to_js(&lamport_sign(&secret, msg)?)
    }
    pub fn verify(public: Vec<String>, msg: &str, reveal: Vec<String>) -> Result<JsValue> {
        to_js(&lamport_verify(&public, msg, &reveal)?)
    }
    pub fn forge(msg1: &str, reveal1: Vec<String>, msg2: &str, reveal2: Vec<String>, attacker_prefix: &str) -> Result<JsValue> {
        to_js(&lamport_forge(msg1, &reveal1, msg2, &reveal2, attacker_prefix)?)
    }
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(|e| CryptoError::new(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat(k: &[[String; 2]]) -> Vec<String> {
        k.iter().flat_map(|p| p.iter().cloned()).collect()
    }

    #[test]
    fn sign_verify_roundtrip_and_tampering_fails() {
        let key = lamport_keygen();
        let (sk, pk) = (flat(&key.secret), flat(&key.public));
        let sig = lamport_sign(&sk, "pay Alice 5").unwrap();
        assert_eq!(sig.reveal.len(), BITS);
        let v = lamport_verify(&pk, "pay Alice 5", &sig.reveal).unwrap();
        assert!(v.verified);
        // The same reveal against a different message fails on the bits that differ.
        let bad = lamport_verify(&pk, "pay Mallory 5000", &sig.reveal).unwrap();
        assert!(!bad.verified);
        // A fresh key has different public hashes.
        let key2 = lamport_keygen();
        assert_ne!(key.public[0][0], key2.public[0][0]);
        assert!(lamport_sign(&sk[1..], "x").is_err());
    }

    #[test]
    fn two_signatures_allow_a_forgery_one_does_not_guarantee_it() {
        let key = lamport_keygen();
        let (sk, pk) = (flat(&key.secret), flat(&key.public));
        let (m1, m2) = ("pay Alice 5", "pay Bob 999");
        let s1 = lamport_sign(&sk, m1).unwrap();
        let s2 = lamport_sign(&sk, m2).unwrap();
        // The differing digest bits are a fixed property of the two messages.
        let d = digest_bits(m1).iter().zip(digest_bits(m2)).filter(|(a, b)| **a != *b).count();
        let f = lamport_forge(m1, &s1.reveal, m2, &s2.reveal, "pay Mallory ").unwrap();
        assert_eq!(f.free_positions.len(), d);
        assert_eq!(f.forgeable_digests, 2f64.powi(d as i32));
        // The search found a forgeable message and its signature verifies.
        let forged = f.forged_message.expect("search space is large enough");
        assert_ne!(forged, m1);
        assert_ne!(forged, m2);
        let v = lamport_verify(&pk, &forged, &f.forged_reveal).unwrap();
        assert!(v.verified, "forged signature must verify against the real public key");
    }
}
