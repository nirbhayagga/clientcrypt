//! The one-time pad: the only cipher with a *proof* of secrecy.
//!
//! XOR the message with a truly random key of the same length, used once.
//! Shannon proved in 1949 that the ciphertext is then statistically independent
//! of the plaintext — every message of that length is an equally good
//! explanation of what was intercepted. The price is a key as long as all
//! traffic, delivered in advance, never reused; break either rule and the
//! scheme collapses, which is what the two-time-pad functions demonstrate.

use crate::{CryptoError, Result};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::Serialize;
use wasm_bindgen::prelude::*;

const MAX_LEN: usize = 4096;

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

fn decode(hex_str: &str, what: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str.trim()).map_err(|_| CryptoError::new(format!("{what} is not valid hex")))
}

#[derive(Serialize)]
pub struct OtpCiphertext {
    pub key_hex: String,
    pub ciphertext_hex: String,
    pub length: u32,
}

/// Encrypt with a fresh random pad the exact length of the message.
pub fn otp_encrypt(plaintext: &str) -> Result<OtpCiphertext> {
    let pt = plaintext.as_bytes();
    if pt.is_empty() {
        return Err(CryptoError::new("Type a message to encrypt"));
    }
    if pt.len() > MAX_LEN {
        return Err(CryptoError::new(format!("Message must be at most {MAX_LEN} bytes")));
    }
    let mut key = vec![0u8; pt.len()];
    OsRng.fill_bytes(&mut key);
    Ok(OtpCiphertext {
        ciphertext_hex: hex::encode(xor(pt, &key)),
        key_hex: hex::encode(key),
        length: pt.len() as u32,
    })
}

/// Decryption is the same XOR; lengths must match exactly.
pub fn otp_decrypt(ciphertext_hex: &str, key_hex: &str) -> Result<String> {
    let ct = decode(ciphertext_hex, "Ciphertext")?;
    let key = decode(key_hex, "Key")?;
    if ct.len() != key.len() {
        return Err(CryptoError::new(format!(
            "Key is {} bytes but the ciphertext is {} — a one-time pad key must match exactly", key.len(), ct.len()
        )));
    }
    Ok(String::from_utf8_lossy(&xor(&ct, &key)).into_owned())
}

/// Perfect secrecy, constructively: for ANY candidate plaintext of the right
/// length there exists a key that "decrypts" the ciphertext to it — so the
/// ciphertext alone cannot prefer one message over another.
pub fn otp_forge_key(ciphertext_hex: &str, desired_plaintext: &str) -> Result<String> {
    let ct = decode(ciphertext_hex, "Ciphertext")?;
    let desired = desired_plaintext.as_bytes();
    if ct.is_empty() {
        return Err(CryptoError::new("Encrypt a message first"));
    }
    if desired.len() != ct.len() {
        return Err(CryptoError::new(format!(
            "The claimed plaintext is {} bytes but the ciphertext is {} — perfect secrecy only hides the content, not the length", desired.len(), ct.len()
        )));
    }
    Ok(hex::encode(xor(&ct, desired)))
}

#[derive(Serialize)]
pub struct PadReuse {
    pub c1_hex: String,
    pub c2_hex: String,
    /// c1 ⊕ c2 over the shorter length — the pad cancels, leaving p1 ⊕ p2.
    pub xor_hex: String,
}

/// Encrypt two messages under the SAME pad and XOR the ciphertexts: the key
/// drops out entirely, leaving the two plaintexts XORed with each other.
pub fn pad_reuse(p1: &str, p2: &str, key_hex: &str) -> Result<PadReuse> {
    let key = decode(key_hex, "Pad")?;
    let (a, b) = (p1.as_bytes(), p2.as_bytes());
    if a.is_empty() || b.is_empty() {
        return Err(CryptoError::new("Type both messages"));
    }
    if key.len() < a.len().max(b.len()) {
        return Err(CryptoError::new(format!(
            "The pad is {} bytes; it must be at least as long as the longer message ({} bytes)", key.len(), a.len().max(b.len())
        )));
    }
    let c1 = xor(a, &key);
    let c2 = xor(b, &key);
    let n = c1.len().min(c2.len());
    Ok(PadReuse {
        xor_hex: hex::encode(xor(&c1[..n], &c2[..n])),
        c1_hex: hex::encode(c1),
        c2_hex: hex::encode(c2),
    })
}

#[derive(Serialize)]
pub struct CribHit {
    pub position: u32,
    /// crib ⊕ (p1 ⊕ p2) at this offset — a fragment of the OTHER plaintext
    /// wherever the crib guess is right.
    pub revealed: String,
}

/// Crib-dragging: slide a guessed word across p1 ⊕ p2 and keep the offsets
/// where XORing it out yields printable text. This is how reused pads were
/// actually read, from WWI field ciphers to the VENONA decryptions.
pub fn crib_drag(xor_hex: &str, crib: &str) -> Result<Vec<CribHit>> {
    let x = decode(xor_hex, "XOR stream")?;
    let c = crib.as_bytes();
    if c.is_empty() {
        return Err(CryptoError::new("Type a crib — a word you guess appears in one message"));
    }
    if c.len() > x.len() {
        return Err(CryptoError::new("The crib is longer than the XOR stream"));
    }
    let mut hits = Vec::new();
    for pos in 0..=(x.len() - c.len()) {
        let out = xor(&x[pos..pos + c.len()], c);
        if out.iter().all(|&b| (0x20..0x7f).contains(&b)) {
            hits.push(CribHit { position: pos as u32, revealed: String::from_utf8_lossy(&out).into_owned() });
            if hits.len() >= 50 {
                break;
            }
        }
    }
    Ok(hits)
}

#[wasm_bindgen]
pub struct Otp;

#[wasm_bindgen]
impl Otp {
    pub fn encrypt(plaintext: &str) -> Result<JsValue> {
        to_js(&otp_encrypt(plaintext)?)
    }

    pub fn decrypt(ciphertext_hex: &str, key_hex: &str) -> Result<String> {
        otp_decrypt(ciphertext_hex, key_hex)
    }

    /// The key that would decrypt this ciphertext to any plaintext you claim.
    pub fn forge_key(ciphertext_hex: &str, desired_plaintext: &str) -> Result<String> {
        otp_forge_key(ciphertext_hex, desired_plaintext)
    }

    /// Two messages under one pad, plus the key-free XOR of the ciphertexts.
    pub fn pad_reuse(p1: &str, p2: &str, key_hex: &str) -> Result<JsValue> {
        to_js(&pad_reuse(p1, p2, key_hex)?)
    }

    pub fn crib_drag(xor_hex: &str, crib: &str) -> Result<JsValue> {
        to_js(&crib_drag(xor_hex, crib)?)
    }
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(|e| CryptoError::new(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_a_fresh_pad_each_time() {
        let a = otp_encrypt("ATTACK AT DAWN").unwrap();
        let b = otp_encrypt("ATTACK AT DAWN").unwrap();
        assert_eq!(otp_decrypt(&a.ciphertext_hex, &a.key_hex).unwrap(), "ATTACK AT DAWN");
        assert_eq!(a.key_hex.len(), 2 * 14);
        assert_eq!(a.length, 14);
        // A fresh pad every time: same plaintext, unrelated ciphertexts.
        assert_ne!(a.ciphertext_hex, b.ciphertext_hex);
        assert!(otp_encrypt("").is_err());
        assert!(otp_decrypt(&a.ciphertext_hex, "00ff").is_err()); // short key
    }

    #[test]
    fn perfect_secrecy_any_plaintext_fits_the_ciphertext() {
        let enc = otp_encrypt("ATTACK AT DAWN").unwrap();
        // Same length, opposite meaning: a key exists that decrypts to it.
        let forged = otp_forge_key(&enc.ciphertext_hex, "RETREAT AT SIX").unwrap();
        assert_eq!(otp_decrypt(&enc.ciphertext_hex, &forged).unwrap(), "RETREAT AT SIX");
        // And it is a different but equally valid-looking uniform key.
        assert_ne!(forged, enc.key_hex);
        // Only the length leaks: a wrong-length claim is refused.
        assert!(otp_forge_key(&enc.ciphertext_hex, "RETREAT NOW").is_err());
    }

    #[test]
    fn reusing_the_pad_cancels_the_key_exactly() {
        let (p1, p2) = ("the attack begins at dawn", "the retreat is now sounded");
        let key = "aa".repeat(32);
        let r = pad_reuse(p1, p2, &key).unwrap();
        // c1 ⊕ c2 = p1 ⊕ p2 — verify against a direct XOR of the plaintexts.
        let direct: Vec<u8> = xor(&p1.as_bytes()[..25], &p2.as_bytes()[..25]);
        assert_eq!(r.xor_hex, hex::encode(direct));
        // The pad's value is irrelevant: any other pad gives the same XOR.
        let r2 = pad_reuse(p1, p2, &"3c".repeat(40)).unwrap();
        assert_eq!(r.xor_hex, r2.xor_hex);
        assert_ne!(r.c1_hex, r2.c1_hex);
        assert!(pad_reuse(p1, p2, "00ff").is_err()); // pad too short
    }

    #[test]
    fn crib_dragging_reads_both_messages() {
        let r = pad_reuse("the attack begins at dawn", "the retreat is now sounded", &"5b".repeat(32)).unwrap();
        // Guessing a word from message 1 reveals message 2 at the right offset.
        let hits = crib_drag(&r.xor_hex, "attack").unwrap();
        let at4 = hits.iter().find(|h| h.position == 4).expect("crib fits at offset 4");
        assert_eq!(at4.revealed, "retrea");
        // Both messages start "the ", so the crib recovers it verbatim.
        let the = crib_drag(&r.xor_hex, "the ").unwrap();
        assert_eq!(the.iter().find(|h| h.position == 0).unwrap().revealed, "the ");
        assert!(crib_drag(&r.xor_hex, "").is_err());
        assert!(crib_drag("00ff", "much too long a crib").is_err());
    }
}
