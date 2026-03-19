use wasm_bindgen::prelude::*;
use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use hex;

#[wasm_bindgen]
pub struct BlockCiphers;

#[wasm_bindgen]
impl BlockCiphers {
    #[wasm_bindgen]
    pub fn aes128_ecb_encrypt(key_hex: &str, plaintext_hex: &str) -> String {
        let key = match hex::decode(key_hex) {
            Ok(k) if k.len() == 16 => k,
            _ => return String::from("Error: Key must be 16 bytes (32 hex chars)"),
        };
        let mut pt = match hex::decode(plaintext_hex) {
            Ok(p) => p,
            _ => return String::from("Error: Invalid plaintext hex"),
        };
        
        let pad_len = 16 - (pt.len() % 16);
        pt.extend(vec![pad_len as u8; pad_len]);

        let cipher = Aes128::new(GenericArray::from_slice(&key));
        let mut out = Vec::new();
        
        for chunk in pt.chunks_exact(16) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            out.extend_from_slice(&block);
        }

        hex::encode(out)
    }

    #[wasm_bindgen]
    pub fn aes128_ecb_decrypt(key_hex: &str, ciphertext_hex: &str) -> String {
        let key = match hex::decode(key_hex) {
            Ok(k) if k.len() == 16 => k,
            _ => return String::from("Error: Key must be 16 bytes (32 hex chars)"),
        };
        let ct = match hex::decode(ciphertext_hex) {
            Ok(c) if c.len() % 16 == 0 => c,
            _ => return String::from("Error: Invalid ciphertext hex or not multiple of 16"),
        };

        if ct.is_empty() { return String::new(); }

        let cipher = Aes128::new(GenericArray::from_slice(&key));
        let mut pt = Vec::new();

        for chunk in ct.chunks_exact(16) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            pt.extend_from_slice(&block);
        }

        let pad_len = *pt.last().unwrap() as usize;
        if pad_len > 16 || pad_len == 0 {
            return String::from("Error: Invalid padding");
        }
        pt.truncate(pt.len() - pad_len);
        hex::encode(pt)
    }

    #[wasm_bindgen]
    pub fn aes128_cbc_encrypt(key_hex: &str, iv_hex: &str, plaintext_hex: &str) -> String {
        let key = match hex::decode(key_hex) {
            Ok(k) if k.len() == 16 => k,
            _ => return String::from("Error: Key must be 16 bytes"),
        };
        let iv = match hex::decode(iv_hex) {
            Ok(i) if i.len() == 16 => i,
            _ => return String::from("Error: IV must be 16 bytes"),
        };
        let mut pt = match hex::decode(plaintext_hex) {
            Ok(p) => p,
            _ => return String::from("Error: Invalid plaintext hex"),
        };
        
        let pad_len = 16 - (pt.len() % 16);
        pt.extend(vec![pad_len as u8; pad_len]);

        let cipher = Aes128::new(GenericArray::from_slice(&key));
        let mut out = Vec::new();
        let mut prev = iv;
        
        for chunk in pt.chunks_exact(16) {
            let mut block = [0u8; 16];
            for i in 0..16 { block[i] = chunk[i] ^ prev[i]; }
            let mut g_block = GenericArray::from(block);
            cipher.encrypt_block(&mut g_block);
            out.extend_from_slice(&g_block);
            prev.copy_from_slice(&g_block);
        }

        hex::encode(out)
    }

    #[wasm_bindgen]
    pub fn aes128_cbc_decrypt(key_hex: &str, iv_hex: &str, ciphertext_hex: &str) -> String {
        let key = match hex::decode(key_hex) {
            Ok(k) if k.len() == 16 => k,
            _ => return String::from("Error: Key must be 16 bytes"),
        };
        let iv = match hex::decode(iv_hex) {
            Ok(i) if i.len() == 16 => i,
            _ => return String::from("Error: IV must be 16 bytes"),
        };
        let ct = match hex::decode(ciphertext_hex) {
            Ok(c) if c.len() % 16 == 0 => c,
            _ => return String::from("Error: Invalid ciphertext hex"),
        };

        if ct.is_empty() { return String::new(); }

        let cipher = Aes128::new(GenericArray::from_slice(&key));
        let mut pt = Vec::new();
        let mut prev = iv;
        
        for chunk in ct.chunks_exact(16) {
            let mut g_block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut g_block);
            for i in 0..16 {
                pt.push(g_block[i] ^ prev[i]);
            }
            prev.copy_from_slice(chunk);
        }

        let pad_len = *pt.last().unwrap() as usize;
        if pad_len > 16 || pad_len == 0 {
            return String::from("Error: Invalid padding");
        }
        pt.truncate(pt.len() - pad_len);
        hex::encode(pt)
    }
}
