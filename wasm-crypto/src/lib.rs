//! ClientCrypt's WebAssembly module.
//!
//! Every exported function either returns a value or a `JsError`; nothing
//! panics across the boundary. A panic would leave the module in an
//! unrecoverable state, so the panic hook below only exists to make an
//! unexpected one readable in the browser console.

use wasm_bindgen::prelude::*;

pub mod classical;
pub mod hashing;
pub mod hash_internals;
pub mod block_ciphers;
pub mod asymmetric;
pub mod password;
pub mod tls;
pub mod numbers;
pub mod protocols;
pub mod wireguard;

/// Error type for every fallible export. It is converted into a JavaScript
/// `Error` only at the wasm boundary, so native unit tests can inspect it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoError(pub String);

impl CryptoError {
    pub fn new(msg: impl Into<String>) -> Self {
        CryptoError(msg.into())
    }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CryptoError {}

impl From<CryptoError> for JsValue {
    fn from(e: CryptoError) -> JsValue {
        JsError::new(&e.0).into()
    }
}

impl From<hex::FromHexError> for CryptoError {
    fn from(_: hex::FromHexError) -> Self {
        CryptoError::new("Invalid hex: expected an even number of 0-9/a-f characters")
    }
}

pub type Result<T> = std::result::Result<T, CryptoError>;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Build-time version of the crate, surfaced in the UI footer.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
