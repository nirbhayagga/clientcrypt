use wasm_bindgen::prelude::*;

pub mod classical;
pub mod hashing;

pub mod block_ciphers;
pub mod asymmetric;
pub mod password;
pub mod tls;

#[wasm_bindgen]
pub fn init_panic_hook() {
    // Optionally connect to console.error
}
