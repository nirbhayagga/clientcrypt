use wasm_bindgen::prelude::*;
use sha2::{Sha256, Digest};
use sha1::Sha1;
use hmac::{Hmac, Mac};
use hex;

type HmacSha256 = Hmac<Sha256>;

#[wasm_bindgen]
pub struct Hasher;

#[wasm_bindgen]
impl Hasher {
    #[wasm_bindgen]
    pub fn sha256(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        hex::encode(result)
    }

    #[wasm_bindgen]
    pub fn sha1(data: &str) -> String {
        let mut hasher = Sha1::new();
        hasher.update(data);
        let result = hasher.finalize();
        hex::encode(result)
    }
    
    #[wasm_bindgen]
    pub fn hmac_sha256(key: &str, data: &str) -> String {
        let mac_result = HmacSha256::new_from_slice(key.as_bytes());
        match mac_result {
            Ok(mut mac) => {
                mac.update(data.as_bytes());
                let result = mac.finalize();
                hex::encode(result.into_bytes())
            },
            Err(_) => String::from("Invalid key length")
        }
    }
}
