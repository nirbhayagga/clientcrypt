use wasm_bindgen::prelude::*;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rand::rngs::OsRng;
use num_bigint::{BigUint, RandBigInt};
use hex;

#[wasm_bindgen]
pub struct AsymmetricCrypto;

#[wasm_bindgen]
impl AsymmetricCrypto {
    #[wasm_bindgen]
    pub fn rsa_generate_keys(bits: u32) -> Vec<String> {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, bits as usize).expect("failed to generate a key");
        let pub_key = RsaPublicKey::from(&priv_key);
        
        let priv_pem = priv_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap_or_default().to_string();
        let pub_pem = pub_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap_or_default().to_string();

        vec![priv_pem, pub_pem]
    }

    #[wasm_bindgen]
    pub fn rsa_encrypt(pub_key_pem: &str, plaintext: &str) -> String {
        let mut rng = OsRng;
        let pub_key = RsaPublicKey::from_pkcs1_pem(pub_key_pem).unwrap();
        let enc_data = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext.as_bytes()).unwrap();
        hex::encode(enc_data)
    }

    #[wasm_bindgen]
    pub fn rsa_decrypt(priv_key_pem: &str, ciphertext_hex: &str) -> String {
        let priv_key = RsaPrivateKey::from_pkcs1_pem(priv_key_pem).unwrap();
        let ct = hex::decode(ciphertext_hex).unwrap();
        let pt = priv_key.decrypt(Pkcs1v15Encrypt, &ct).unwrap();
        String::from_utf8(pt).unwrap_or_default()
    }

    #[wasm_bindgen]
    pub fn dh_generate_params(bits: u32) -> Vec<String> {
        // Simplified DH: Generates a prime P and generator G
        // In a real app we'd use standardized parameters
        let mut rng = OsRng;
        let base_prime = rng.gen_biguint(bits as u64); // Not a safe prime generation just for educational demo
        let g = BigUint::from(2u32);
        
        vec![base_prime.to_str_radix(10), g.to_str_radix(10)]
    }

    #[wasm_bindgen]
    pub fn dh_compute_public(p_str: &str, g_str: &str, private_val: &str) -> String {
        let p = BigUint::parse_bytes(p_str.as_bytes(), 10).unwrap();
        let g = BigUint::parse_bytes(g_str.as_bytes(), 10).unwrap();
        let private = BigUint::parse_bytes(private_val.as_bytes(), 10).unwrap();
        
        let pub_val = g.modpow(&private, &p);
        pub_val.to_str_radix(10)
    }

    #[wasm_bindgen]
    pub fn dh_compute_shared(p_str: &str, others_pub: &str, private_val: &str) -> String {
        let p = BigUint::parse_bytes(p_str.as_bytes(), 10).unwrap();
        let other = BigUint::parse_bytes(others_pub.as_bytes(), 10).unwrap();
        let private = BigUint::parse_bytes(private_val.as_bytes(), 10).unwrap();
        
        let shared = other.modpow(&private, &p);
        shared.to_str_radix(10)
    }
}
