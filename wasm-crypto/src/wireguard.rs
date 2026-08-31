//! The WireGuard handshake (Noise IKpsk2, Curve25519 / ChaCha20-Poly1305 /
//! BLAKE2s), following the protocol described at wireguard.com/protocol.
//!
//! This runs both peers locally and returns the trace plus the four transport
//! keys. Correctness is self-checked: the initiator and responder derive their
//! chaining keys and transport keys independently, and they must agree.

use crate::{CryptoError, Result};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::SimpleHkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    for p in parts { h.update(p); }
    h.finalize().into()
}

/// WireGuard KDF_n: HKDF-BLAKE2s(chaining_key, input) split into n 32-byte keys.
fn kdf<const N: usize>(key: &[u8], input: &[u8]) -> [[u8; 32]; N] {
    let hk = SimpleHkdf::<Blake2s256>::new(Some(key), input);
    let mut okm = vec![0u8; N * 32];
    hk.expand(&[], &mut okm).expect("N*32 within BLAKE2s HKDF limit");
    let mut out = [[0u8; 32]; N];
    for (i, chunk) in okm.chunks_exact(32).enumerate() { out[i].copy_from_slice(chunk); }
    out
}

fn dh(secret: &StaticSecret, public: &[u8; 32]) -> [u8; 32] {
    *secret.diffie_hellman(&PublicKey::from(*public)).as_bytes()
}

/// AEAD with a WireGuard counter nonce (32 zero bits ‖ 64-bit little-endian).
fn seal(key: &[u8; 32], counter: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("ChaCha20-Poly1305 encryption is infallible")
}

fn open(key: &[u8; 32], counter: u64, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::new("WireGuard AEAD authentication failed"))
}

fn keypair() -> (StaticSecret, [u8; 32]) {
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    let sk = StaticSecret::from(sk_bytes);
    let pk = *PublicKey::from(&sk).as_bytes();
    (sk, pk)
}

#[derive(Serialize)]
pub struct WgHandshake {
    pub construction_hash: String,
    pub initiator_static_pub: String,
    pub responder_static_pub: String,
    pub initiator_ephemeral_pub: String,
    pub responder_ephemeral_pub: String,
    pub encrypted_static: String,
    pub encrypted_timestamp: String,
    pub encrypted_empty: String,
    pub initiator_chaining_key: String,
    pub responder_chaining_key: String,
    pub keys_agree: bool,
    pub initiator_sending_key: String,
    pub initiator_receiving_key: String,
    pub responder_sending_key: String,
    pub responder_receiving_key: String,
}

pub fn run_handshake(preshared_key_hex: &str, unix_seconds: u64) -> Result<WgHandshake> {
    let psk: [u8; 32] = if preshared_key_hex.trim().is_empty() {
        [0u8; 32]
    } else {
        hex::decode(preshared_key_hex)?.try_into().map_err(|_| CryptoError::new("Pre-shared key must be 32 bytes"))?
    };

    let (i_static, i_static_pub) = keypair();
    let (r_static, r_static_pub) = keypair();
    let (i_eph, i_eph_pub) = keypair();
    let (r_eph, r_eph_pub) = keypair();

    // Both peers start from the same public constants and the responder's
    // static key (which the initiator knows in advance — the "I" of IK).
    let c0 = hash(&[CONSTRUCTION]);
    let h0 = hash(&[&hash(&[&c0, IDENTIFIER]), &r_static_pub]);

    // ---- Initiator builds the first message ----
    let [ci1] = kdf::<1>(&c0, &i_eph_pub);
    let hi1 = hash(&[&h0, &i_eph_pub]);
    let [ci2, k1] = kdf::<2>(&ci1, &dh(&i_eph, &r_static_pub));
    let enc_static = seal(&k1, 0, &i_static_pub, &hi1);
    let hi2 = hash(&[&hi1, &enc_static]);
    let [ci3, k2] = kdf::<2>(&ci2, &dh(&i_static, &r_static_pub));
    let timestamp = tai64n(unix_seconds);
    let enc_timestamp = seal(&k2, 0, &timestamp, &hi2);
    let hi3 = hash(&[&hi2, &enc_timestamp]);

    // ---- Responder consumes the first message, then builds the second ----
    // Recompute the chain from the responder's side and recover the peer static.
    let [r_ci1] = kdf::<1>(&c0, &i_eph_pub);
    let r_hi1 = hash(&[&h0, &i_eph_pub]);
    let [r_ci2, r_k1] = kdf::<2>(&r_ci1, &dh(&r_static, &i_eph_pub));
    let recovered_static = open(&r_k1, 0, &enc_static, &r_hi1)?;
    if recovered_static != i_static_pub { return Err(CryptoError::new("Static key mismatch")); }
    let recovered_pub: [u8; 32] = recovered_static.try_into().unwrap();
    let r_hi2 = hash(&[&r_hi1, &enc_static]);
    let [mut cr, r_k2] = kdf::<2>(&r_ci2, &dh(&r_static, &recovered_pub));
    open(&r_k2, 0, &enc_timestamp, &r_hi2)?; // authenticate the timestamp
    let r_hi3 = hash(&[&r_hi2, &enc_timestamp]);

    let [cr1] = kdf::<1>(&cr, &r_eph_pub);
    let hr1 = hash(&[&r_hi3, &r_eph_pub]);
    let [cr2] = kdf::<1>(&cr1, &dh(&r_eph, &i_eph_pub));
    let [cr3] = kdf::<1>(&cr2, &dh(&r_eph, &recovered_pub));
    let [cr4, tau, k3] = kdf::<3>(&cr3, &psk);
    let hr2 = hash(&[&hr1, &tau]);
    let enc_empty = seal(&k3, 0, &[], &hr2);
    cr = cr4;

    // ---- Initiator consumes the second message ----
    let [i_cr1] = kdf::<1>(&ci3, &r_eph_pub);
    let i_hr1 = hash(&[&hi3, &r_eph_pub]);
    let [i_cr2] = kdf::<1>(&i_cr1, &dh(&i_eph, &r_eph_pub));
    let [i_cr3] = kdf::<1>(&i_cr2, &dh(&i_static, &r_eph_pub));
    let [i_cr4, i_tau, i_k3] = kdf::<3>(&i_cr3, &psk);
    let i_hr2 = hash(&[&i_hr1, &i_tau]);
    open(&i_k3, 0, &enc_empty, &i_hr2)?; // initiator authenticates the responder

    // Transport keys: KDF2(final chaining key, ""). The initiator's sending key
    // is the responder's receiving key and vice versa.
    let [i_send, i_recv] = kdf::<2>(&i_cr4, &[]);
    let [r_recv, r_send] = kdf::<2>(&cr, &[]);
    // The two directions are the same keys seen from opposite ends:
    // T1 = initiator→responder, T2 = responder→initiator.

    Ok(WgHandshake {
        construction_hash: hex::encode(c0),
        initiator_static_pub: hex::encode(i_static_pub),
        responder_static_pub: hex::encode(r_static_pub),
        initiator_ephemeral_pub: hex::encode(i_eph_pub),
        responder_ephemeral_pub: hex::encode(r_eph_pub),
        encrypted_static: hex::encode(&enc_static),
        encrypted_timestamp: hex::encode(&enc_timestamp),
        encrypted_empty: hex::encode(&enc_empty),
        initiator_chaining_key: hex::encode(i_cr4),
        responder_chaining_key: hex::encode(cr),
        keys_agree: i_cr4 == cr && i_send == r_recv && i_recv == r_send,
        initiator_sending_key: hex::encode(i_send),
        initiator_receiving_key: hex::encode(i_recv),
        responder_sending_key: hex::encode(r_send),
        responder_receiving_key: hex::encode(r_recv),
    })
}

/// A 12-byte TAI64N timestamp built from a caller-supplied Unix time. The
/// crate never reads a clock: `wasm32-unknown-unknown` has no time source, so
/// `SystemTime::now()` panics there. The value is opaque to key agreement.
fn tai64n(unix_seconds: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&(0x4000_0000_0000_0000u64 + unix_seconds).to_be_bytes());
    out
}

#[wasm_bindgen]
pub struct WireGuard;

#[wasm_bindgen]
impl WireGuard {
    /// Runs one Noise IKpsk2 handshake. `preshared_key_hex` is optional
    /// (empty = the all-zero PSK, i.e. none); `unix_seconds` supplies the
    /// handshake timestamp, which the caller reads from the JavaScript clock.
    pub fn handshake(preshared_key_hex: &str, unix_seconds: u64) -> Result<JsValue> {
        serde_wasm_bindgen::to_value(&run_handshake(preshared_key_hex, unix_seconds)?).map_err(|e| CryptoError::new(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_hash_is_the_wireguard_constant() {
        // BLAKE2s("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s").
        assert_eq!(hex::encode(hash(&[CONSTRUCTION])),
            "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36");
    }

    #[test]
    fn both_peers_derive_the_same_transport_keys() {
        let hs = run_handshake("", 1_756_500_000).unwrap();
        assert!(hs.keys_agree);
        assert_eq!(hs.initiator_chaining_key, hs.responder_chaining_key);
        assert_eq!(hs.initiator_sending_key, hs.responder_receiving_key);
        assert_eq!(hs.initiator_receiving_key, hs.responder_sending_key);
        // Distinct directions, and the encrypted static field is 32 + 16 bytes.
        assert_ne!(hs.initiator_sending_key, hs.initiator_receiving_key);
        assert_eq!(hs.encrypted_static.len(), (32 + 16) * 2);
        assert_eq!(hs.encrypted_empty.len(), 16 * 2);
    }

    #[test]
    fn a_preshared_key_changes_the_result_and_must_be_32_bytes() {
        let none = run_handshake("", 1_756_500_000).unwrap();
        let psk = run_handshake(&"ab".repeat(32), 1_756_500_000).unwrap();
        assert!(psk.keys_agree);
        assert_ne!(none.initiator_sending_key, psk.initiator_sending_key);
        assert!(run_handshake("00ff", 0).is_err());
    }
}
