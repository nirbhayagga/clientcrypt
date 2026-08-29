use wasm_bindgen::prelude::*;
use sha2::{Sha256, Digest};

#[wasm_bindgen]
pub struct PasswordSecurity;

#[wasm_bindgen]
impl PasswordSecurity {
    #[wasm_bindgen]
    pub fn calculate_entropy(password: &str) -> f64 {
        let len = password.chars().count() as f64;
        let mut pool: f64 = 0.0;
        
        if password.chars().any(|c| c.is_lowercase()) { pool += 26.0; }
        if password.chars().any(|c| c.is_uppercase()) { pool += 26.0; }
        if password.chars().any(|c| c.is_numeric()) { pool += 10.0; }
        if password.chars().any(|c| !c.is_alphanumeric()) { pool += 32.0; }
        
        if pool == 0.0 {
            return 0.0;
        }
        
        len * pool.log2()
    }

    #[wasm_bindgen]
    pub fn time_to_crack_classical(entropy: f64) -> f64 {
        let guesses = 2f64.powf(entropy);
        guesses / 10_000_000_000.0
    }

    #[wasm_bindgen]
    pub fn time_to_crack_quantum(entropy: f64) -> f64 {
        let guesses = 2f64.powf(entropy / 2.0);
        guesses / 10_000_000_000.0
    }

    #[wasm_bindgen]
    pub fn check_dictionary(password: &str, wordlist: &str) -> bool {
        wordlist.lines().any(|line| line == password)
    }

    /// Chains `iterations` SHA-256 computations (each input is the previous
    /// digest) and returns the final digest. Timing is done by the caller.
    #[wasm_bindgen]
    pub fn benchmark_sha256(iterations: u32) -> String {
        let mut data = [0u8; 32];
        for _ in 0..iterations {
            data = Sha256::digest(data).into();
        }
        hex::encode(data)
    }
}
