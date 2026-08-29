//! AES (FIPS 197) in the ECB, CBC and CTR modes of SP 800-38A and the GCM
//! authenticated mode of SP 800-38D. Key sizes 128, 192 and 256 bits.

use crate::{CryptoError, Result};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AesGcm, Aes128Gcm, Aes256Gcm};
use aes_gcm::aes::cipher::consts::U12;
use wasm_bindgen::prelude::*;

const BLOCK: usize = 16;

enum Aes { K128(Aes128), K192(Aes192), K256(Aes256) }

impl Aes {
    fn new(key: &[u8]) -> Result<Self> {
        Ok(match key.len() {
            16 => Aes::K128(Aes128::new(GenericArray::from_slice(key))),
            24 => Aes::K192(Aes192::new(GenericArray::from_slice(key))),
            32 => Aes::K256(Aes256::new(GenericArray::from_slice(key))),
            n => return Err(CryptoError::new(format!("Key must be 16, 24 or 32 bytes (got {n})"))),
        })
    }
    fn enc(&self, b: &mut [u8; BLOCK]) {
        let g = GenericArray::from_mut_slice(b);
        match self { Aes::K128(c) => c.encrypt_block(g), Aes::K192(c) => c.encrypt_block(g), Aes::K256(c) => c.encrypt_block(g) }
    }
    fn dec(&self, b: &mut [u8; BLOCK]) {
        let g = GenericArray::from_mut_slice(b);
        match self { Aes::K128(c) => c.decrypt_block(g), Aes::K192(c) => c.decrypt_block(g), Aes::K256(c) => c.decrypt_block(g) }
    }
}

fn need_iv(iv: &[u8]) -> Result<[u8; BLOCK]> {
    iv.try_into().map_err(|_| CryptoError::new(format!("IV must be 16 bytes (got {})", iv.len())))
}

fn need_blocks(data: &[u8], what: &str) -> Result<()> {
    if data.len() % BLOCK != 0 {
        return Err(CryptoError::new(format!("{what} length must be a multiple of 16 bytes (got {})", data.len())));
    }
    Ok(())
}

pub fn pkcs7_pad(mut data: Vec<u8>) -> Vec<u8> {
    let pad = BLOCK - data.len() % BLOCK;
    data.extend(std::iter::repeat_n(pad as u8, pad));
    data
}

/// Strict PKCS#7 unpadding: every padding byte is checked, not just the last.
pub fn pkcs7_unpad(mut data: Vec<u8>) -> Result<Vec<u8>> {
    let pad = *data.last().ok_or_else(|| CryptoError::new("Invalid padding: empty input"))? as usize;
    if pad == 0 || pad > BLOCK || pad > data.len() || data[data.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err(CryptoError::new("Invalid padding"));
    }
    data.truncate(data.len() - pad);
    Ok(data)
}

fn xor_into(dst: &mut [u8; BLOCK], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) { *d ^= s; }
}

fn ctr_increment(counter: &mut [u8; BLOCK]) {
    for b in counter.iter_mut().rev() {
        *b = b.wrapping_add(1);
        if *b != 0 { break; }
    }
}

/// Core of the non-authenticated modes. `data` must already be padded for
/// ECB/CBC; CTR accepts any length.
pub fn aes_mode_raw(mode: &str, key: &[u8], iv: &[u8], data: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    let cipher = Aes::new(key)?;
    match mode {
        "ecb" => {
            need_blocks(data, "Input")?;
            let mut out = Vec::with_capacity(data.len());
            for chunk in data.chunks_exact(BLOCK) {
                let mut b: [u8; BLOCK] = chunk.try_into().unwrap();
                if encrypt { cipher.enc(&mut b) } else { cipher.dec(&mut b) }
                out.extend_from_slice(&b);
            }
            Ok(out)
        }
        "cbc" => {
            need_blocks(data, "Input")?;
            let mut prev = need_iv(iv)?;
            let mut out = Vec::with_capacity(data.len());
            for chunk in data.chunks_exact(BLOCK) {
                let mut b: [u8; BLOCK] = chunk.try_into().unwrap();
                if encrypt {
                    xor_into(&mut b, &prev);
                    cipher.enc(&mut b);
                    prev = b;
                } else {
                    cipher.dec(&mut b);
                    xor_into(&mut b, &prev);
                    prev = chunk.try_into().unwrap();
                }
                out.extend_from_slice(&b);
            }
            Ok(out)
        }
        "ctr" => {
            let mut counter = need_iv(iv)?;
            let mut out = Vec::with_capacity(data.len());
            for chunk in data.chunks(BLOCK) {
                let mut ks = counter;
                cipher.enc(&mut ks);
                out.extend(chunk.iter().zip(ks.iter()).map(|(d, k)| d ^ k));
                ctr_increment(&mut counter);
            }
            Ok(out)
        }
        other => Err(CryptoError::new(format!("Unknown mode '{other}' (ecb, cbc, ctr)"))),
    }
}

fn gcm_seal(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(CryptoError::new(format!("GCM nonce must be 12 bytes (got {})", nonce.len())));
    }
    let n = aes_gcm::Nonce::from_slice(nonce);
    let payload = Payload { msg: data, aad };
    let fail = |_| CryptoError::new(if encrypt { "Encryption failed" } else { "Authentication failed: ciphertext, tag, key, nonce or AAD does not match" });
    match key.len() {
        16 => { let c = Aes128Gcm::new(GenericArray::from_slice(key)); if encrypt { c.encrypt(n, payload) } else { c.decrypt(n, payload) }.map_err(fail) }
        24 => { let c = AesGcm::<Aes192, U12>::new(GenericArray::from_slice(key)); if encrypt { c.encrypt(n, payload) } else { c.decrypt(n, payload) }.map_err(fail) }
        32 => { let c = Aes256Gcm::new(GenericArray::from_slice(key)); if encrypt { c.encrypt(n, payload) } else { c.decrypt(n, payload) }.map_err(fail) }
        len => Err(CryptoError::new(format!("Key must be 16, 24 or 32 bytes (got {len})"))),
    }
}

#[wasm_bindgen]
pub struct BlockCiphers;

#[wasm_bindgen]
impl BlockCiphers {
    /// Encrypts `data_hex`. ECB/CBC apply PKCS#7 padding; CTR does not pad.
    /// `iv_hex` is ignored for ECB.
    pub fn aes_encrypt(mode: &str, key_hex: &str, iv_hex: &str, data_hex: &str) -> Result<String> {
        let key = hex::decode(key_hex)?;
        let iv = hex::decode(iv_hex)?;
        let data = hex::decode(data_hex)?;
        let input = if mode == "ctr" { data } else { pkcs7_pad(data) };
        Ok(hex::encode(aes_mode_raw(mode, &key, &iv, &input, true)?))
    }

    /// Inverse of `aes_encrypt`; ECB/CBC validate and strip PKCS#7 padding.
    pub fn aes_decrypt(mode: &str, key_hex: &str, iv_hex: &str, data_hex: &str) -> Result<String> {
        let key = hex::decode(key_hex)?;
        let iv = hex::decode(iv_hex)?;
        let data = hex::decode(data_hex)?;
        let out = aes_mode_raw(mode, &key, &iv, &data, false)?;
        Ok(hex::encode(if mode == "ctr" { out } else { pkcs7_unpad(out)? }))
    }

    /// AES-GCM. Returns ciphertext ‖ 16-byte tag.
    pub fn aes_gcm_encrypt(key_hex: &str, nonce_hex: &str, aad_hex: &str, data_hex: &str) -> Result<String> {
        Ok(hex::encode(gcm_seal(&hex::decode(key_hex)?, &hex::decode(nonce_hex)?, &hex::decode(aad_hex)?, &hex::decode(data_hex)?, true)?))
    }

    /// AES-GCM open; input is ciphertext ‖ tag. Fails if anything was altered.
    pub fn aes_gcm_decrypt(key_hex: &str, nonce_hex: &str, aad_hex: &str, data_hex: &str) -> Result<String> {
        Ok(hex::encode(gcm_seal(&hex::decode(key_hex)?, &hex::decode(nonce_hex)?, &hex::decode(aad_hex)?, &hex::decode(data_hex)?, false)?))
    }

    /// Unpadded raw encryption of a byte buffer (for the image demonstration).
    /// ECB/CBC require a multiple of 16 bytes.
    pub fn aes_encrypt_bytes(mode: &str, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        aes_mode_raw(mode, key, iv, data, true)
    }

    /// PKCS#7 padding of a hex string, for display.
    pub fn pkcs7_pad_hex(data_hex: &str) -> Result<String> {
        Ok(hex::encode(pkcs7_pad(hex::decode(data_hex)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> { hex::decode(s).unwrap() }

    #[test]
    fn fips_197_appendix_c_known_answers() {
        let pt = "00112233445566778899aabbccddeeff";
        let cases = [
            ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
            ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
        ];
        for (key, ct) in cases {
            let out = aes_mode_raw("ecb", &h(key), &[], &h(pt), true).unwrap();
            assert_eq!(hex::encode(&out), ct);
            assert_eq!(hex::encode(aes_mode_raw("ecb", &h(key), &[], &out, false).unwrap()), pt);
        }
    }

    #[test]
    fn sp800_38a_cbc_and_ctr_vectors() {
        let key = "2b7e151628aed2a6abf7158809cf4f3c";
        let pt = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";
        let cbc = aes_mode_raw("cbc", &h(key), &h("000102030405060708090a0b0c0d0e0f"), &h(pt), true).unwrap();
        assert_eq!(hex::encode(&cbc), "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2");
        let ctr = aes_mode_raw("ctr", &h(key), &h("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), &h(pt), true).unwrap();
        assert_eq!(hex::encode(&ctr), "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff");
        assert_eq!(hex::encode(aes_mode_raw("ctr", &h(key), &h("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), &ctr, false).unwrap()), pt);
    }

    #[test]
    fn gcm_spec_test_cases() {
        let zero_key = "00000000000000000000000000000000";
        let nonce = "000000000000000000000000";
        assert_eq!(BlockCiphers::aes_gcm_encrypt(zero_key, nonce, "", "").unwrap(), "58e2fccefa7e3061367f1d57a4e7455a");
        let ct = BlockCiphers::aes_gcm_encrypt(zero_key, nonce, "", "00000000000000000000000000000000").unwrap();
        assert_eq!(ct, "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");
        assert_eq!(BlockCiphers::aes_gcm_decrypt(zero_key, nonce, "", &ct).unwrap(), "00000000000000000000000000000000");
        let mut tampered = ct.clone();
        tampered.replace_range(0..1, "1");
        assert!(BlockCiphers::aes_gcm_decrypt(zero_key, nonce, "", &tampered).is_err());
        assert!(BlockCiphers::aes_gcm_decrypt(zero_key, nonce, "ff", &ct).is_err());
    }

    #[test]
    fn padding_is_applied_and_strictly_validated() {
        assert_eq!(pkcs7_pad(vec![1, 2, 3]).len(), 16);
        assert_eq!(pkcs7_pad(vec![0; 16]).len(), 32);
        assert_eq!(pkcs7_unpad(pkcs7_pad(vec![9; 20])).unwrap(), vec![9; 20]);
        assert!(pkcs7_unpad(vec![1, 2, 3, 0]).is_err());
        assert!(pkcs7_unpad(vec![1, 2, 2, 3]).is_err());
        assert!(pkcs7_unpad(vec![17; 32]).is_err());
        let ct = BlockCiphers::aes_encrypt("cbc", "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f", "abcdef").unwrap();
        assert_eq!(ct.len(), 32);
        assert_eq!(BlockCiphers::aes_decrypt("cbc", "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f", &ct).unwrap(), "abcdef");
    }

    #[test]
    fn errors_are_reported_not_panicked() {
        assert!(BlockCiphers::aes_encrypt("ecb", "0011", "", "00").is_err());
        assert!(BlockCiphers::aes_encrypt("cbc", "000102030405060708090a0b0c0d0e0f", "00", "00").is_err());
        assert!(BlockCiphers::aes_encrypt("xyz", "000102030405060708090a0b0c0d0e0f", "", "00").is_err());
        assert!(BlockCiphers::aes_decrypt("ecb", "000102030405060708090a0b0c0d0e0f", "", "00").is_err());
        assert!(BlockCiphers::aes_encrypt("ecb", "zz", "", "00").is_err());
    }
}
