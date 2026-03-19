use wasm_bindgen::prelude::*;
use num_bigint::{BigUint, RandBigInt};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use rand::Rng;
use hex;

type HmacSha256 = Hmac<Sha256>;

#[wasm_bindgen]
pub struct TlsSimulator {
    client_random: String,
    server_random: String,
    p: String,
    g: String,
    server_private_dh: String,
    server_public_dh: String,
    client_private_dh: String,
    client_public_dh: String,
    shared_secret: String,
    session_key: String,
}

#[wasm_bindgen]
impl TlsSimulator {
    #[wasm_bindgen(constructor)]
    pub fn new() -> TlsSimulator {
        TlsSimulator {
            client_random: String::new(),
            server_random: String::new(),
            p: String::new(),
            g: String::new(),
            server_private_dh: String::new(),
            server_public_dh: String::new(),
            client_private_dh: String::new(),
            client_public_dh: String::new(),
            shared_secret: String::new(),
            session_key: String::new(),
        }
    }

    #[wasm_bindgen]
    pub fn client_hello(&mut self) -> String {
        let mut rng = OsRng;
        let mut random_bytes = [0u8; 32];
        rng.fill(&mut random_bytes);
        self.client_random = hex::encode(random_bytes);
        self.client_random.clone()
    }

    #[wasm_bindgen]
    pub fn server_hello(&mut self) -> Vec<String> {
        let mut rng = OsRng;
        let mut random_bytes = [0u8; 32];
        rng.fill(&mut random_bytes);
        self.server_random = hex::encode(random_bytes);
        
        let p = rng.gen_biguint(256); // 256-bit prime for demo speed
        let g = BigUint::from(2u32);
        self.p = p.to_str_radix(10);
        self.g = g.to_str_radix(10);
        
        let server_priv = rng.gen_biguint(256);
        self.server_private_dh = server_priv.to_str_radix(10);
        let server_pub = g.modpow(&server_priv, &p);
        self.server_public_dh = server_pub.to_str_radix(10);

        vec![
            self.server_random.clone(),
            self.p.clone(),
            self.g.clone(),
            self.server_public_dh.clone()
        ]
    }

    #[wasm_bindgen]
    pub fn client_key_exchange(&mut self) -> String {
        let mut rng = OsRng;
        let p = BigUint::parse_bytes(self.p.as_bytes(), 10).unwrap();
        let g = BigUint::parse_bytes(self.g.as_bytes(), 10).unwrap();
        
        let client_priv = rng.gen_biguint(256);
        self.client_private_dh = client_priv.to_str_radix(10);
        
        let client_pub = g.modpow(&client_priv, &p);
        self.client_public_dh = client_pub.to_str_radix(10);
        
        let server_pub = BigUint::parse_bytes(self.server_public_dh.as_bytes(), 10).unwrap();
        let shared = server_pub.modpow(&client_priv, &p);
        self.shared_secret = hex::encode(shared.to_bytes_be());
        
        let mut mac = HmacSha256::new_from_slice(self.shared_secret.as_bytes()).unwrap();
        let seed = format!("{}{}", self.client_random, self.server_random);
        mac.update(seed.as_bytes());
        let result = mac.finalize();
        self.session_key = hex::encode(&result.into_bytes()[..16]); // 16 bytes for AES-128
        
        self.client_public_dh.clone()
    }

    #[wasm_bindgen]
    pub fn server_derive_key(&mut self) -> String {
        let p = BigUint::parse_bytes(self.p.as_bytes(), 10).unwrap();
        let server_priv = BigUint::parse_bytes(self.server_private_dh.as_bytes(), 10).unwrap();
        let client_pub = BigUint::parse_bytes(self.client_public_dh.as_bytes(), 10).unwrap();
        
        let shared = client_pub.modpow(&server_priv, &p);
        let shared_hex = hex::encode(shared.to_bytes_be());
        
        let mut mac = HmacSha256::new_from_slice(shared_hex.as_bytes()).unwrap();
        let seed = format!("{}{}", self.client_random, self.server_random);
        mac.update(seed.as_bytes());
        let result = mac.finalize();
        let derived_key = hex::encode(&result.into_bytes()[..16]);
        
        if derived_key == self.session_key {
            String::from("Success!")
        } else {
            String::from("Error: Key mismatch!")
        }
    }

    #[wasm_bindgen]
    pub fn get_session_key(&self) -> String {
        self.session_key.clone()
    }
}
