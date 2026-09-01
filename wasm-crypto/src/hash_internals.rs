//! SHA-256 with its internals exposed (FIPS 180-4 §6.2), and the length
//! extension attack that follows from the Merkle–Damgård construction.
//!
//! The `sha2` crate is the implementation used everywhere else on the site;
//! this module re-implements the same function so the message schedule and the
//! round-by-round state can be shown. The tests check it against `sha2`.

use crate::{CryptoError, Result};
use serde::Serialize;
use wasm_bindgen::prelude::*;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// The padding SHA-256 appends: 0x80, zeros, then the 64-bit big-endian length.
pub fn padding_for(byte_len: u64) -> Vec<u8> {
    let mut pad = vec![0x80u8];
    while (byte_len as usize + pad.len()) % 64 != 56 {
        pad.push(0);
    }
    pad.extend_from_slice(&(byte_len * 8).to_be_bytes());
    pad
}

fn schedule(block: &[u8; 64]) -> [u32; 64] {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    w
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let w = schedule(block);
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g; g = f; f = e; e = d.wrapping_add(t1);
        d = c; c = b; b = a; a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

/// SHA-256 starting from an arbitrary chaining value and message-length prefix.
/// With `state = H0` and `prior_len = 0` this is plain SHA-256; with a state
/// recovered from someone else's digest it continues *their* hash.
pub fn sha256_from(state: [u32; 8], prior_len: u64, message: &[u8]) -> [u8; 32] {
    let mut state = state;
    let mut buf = message.to_vec();
    buf.extend_from_slice(&padding_for(prior_len + message.len() as u64));
    for chunk in buf.chunks_exact(64) {
        compress(&mut state, chunk.try_into().unwrap());
    }
    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn sha256(message: &[u8]) -> [u8; 32] {
    sha256_from(H0, 0, message)
}

#[derive(Serialize)]
pub struct Round {
    pub index: u32,
    pub w: String,
    pub k: String,
    pub t1: String,
    pub t2: String,
    pub state: Vec<String>,
}

#[derive(Serialize)]
pub struct Sha256Trace {
    pub message_len: usize,
    pub padded_len: usize,
    pub block_count: usize,
    pub block_index: usize,
    pub block_hex: String,
    pub padding_hex: String,
    /// W[0..63], the message schedule for the selected block.
    pub schedule: Vec<String>,
    pub rounds: Vec<Round>,
    pub state_in: Vec<String>,
    pub state_out: Vec<String>,
    pub digest: String,
}

pub fn trace(message: &[u8], block_index: usize) -> Result<Sha256Trace> {
    let pad = padding_for(message.len() as u64);
    let mut padded = message.to_vec();
    padded.extend_from_slice(&pad);
    let blocks: Vec<&[u8]> = padded.chunks_exact(64).collect();
    if block_index >= blocks.len() {
        return Err(CryptoError::new(format!("Block {block_index} does not exist (message has {} blocks)", blocks.len())));
    }

    // Run up to the requested block to get the chaining value going into it.
    let mut state = H0;
    for b in &blocks[..block_index] {
        compress(&mut state, (*b).try_into().unwrap());
    }
    let state_in = state;
    let block: [u8; 64] = blocks[block_index].try_into().unwrap();
    let w = schedule(&block);

    // Re-run the selected block, recording every round.
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state_in;
    let hexes = |v: [u32; 8]| v.iter().map(|x| format!("{x:08x}")).collect::<Vec<_>>();
    let mut rounds = Vec::with_capacity(64);
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g; g = f; f = e; e = d.wrapping_add(t1);
        d = c; c = b; b = a; a = t1.wrapping_add(t2);
        rounds.push(Round {
            index: i as u32,
            w: format!("{:08x}", w[i]),
            k: format!("{:08x}", K[i]),
            t1: format!("{t1:08x}"),
            t2: format!("{t2:08x}"),
            state: hexes([a, b, c, d, e, f, g, h]),
        });
    }
    let mut state_out = state_in;
    for (s, v) in state_out.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }

    Ok(Sha256Trace {
        message_len: message.len(),
        padded_len: padded.len(),
        block_count: blocks.len(),
        block_index,
        block_hex: hex::encode(block),
        padding_hex: hex::encode(&pad),
        schedule: w.iter().map(|x| format!("{x:08x}")).collect(),
        rounds,
        state_in: hexes(state_in),
        state_out: hexes(state_out),
        digest: hex::encode(sha256(message)),
    })
}

#[derive(Serialize)]
pub struct LengthExtension {
    pub original_digest: String,
    pub recovered_state: Vec<String>,
    pub glue_padding_hex: String,
    pub forged_message_hex: String,
    pub forged_digest: String,
    pub genuine_digest: String,
    pub attack_succeeded: bool,
}

/// The length extension attack. Knowing only `H(secret ‖ message)` and the
/// length of the secret, append `suffix` and compute the valid digest for
/// `secret ‖ message ‖ glue padding ‖ suffix` — without knowing the secret.
///
/// `secret` is supplied only so the page can show that the forged digest
/// matches the genuine one; the attack itself never reads it.
pub fn length_extension(digest_hex: &str, secret_len: u64, message: &[u8], suffix: &[u8], secret: &[u8]) -> Result<LengthExtension> {
    let digest = hex::decode(digest_hex)?;
    let digest: [u8; 32] = digest.try_into().map_err(|_| CryptoError::new("Digest must be 32 bytes"))?;

    // A SHA-256 digest *is* the internal state: read it straight back out.
    let mut state = [0u32; 8];
    for (i, word) in state.iter_mut().enumerate() {
        *word = u32::from_be_bytes(digest[i * 4..i * 4 + 4].try_into().unwrap());
    }

    let original_len = secret_len + message.len() as u64;
    let glue = padding_for(original_len);
    let forged_digest = sha256_from(state, original_len + glue.len() as u64, suffix);

    // What the holder of the secret would compute for the same extended input.
    let mut genuine_input = secret.to_vec();
    genuine_input.extend_from_slice(message);
    genuine_input.extend_from_slice(&glue);
    genuine_input.extend_from_slice(suffix);
    let genuine = sha256(&genuine_input);

    let mut forged_message = message.to_vec();
    forged_message.extend_from_slice(&glue);
    forged_message.extend_from_slice(suffix);

    Ok(LengthExtension {
        original_digest: digest_hex.to_string(),
        recovered_state: state.iter().map(|x| format!("{x:08x}")).collect(),
        glue_padding_hex: hex::encode(&glue),
        forged_message_hex: hex::encode(&forged_message),
        forged_digest: hex::encode(forged_digest),
        genuine_digest: hex::encode(genuine),
        attack_succeeded: forged_digest == genuine,
    })
}

#[wasm_bindgen]
pub struct HashInternals;

#[wasm_bindgen]
impl HashInternals {
    /// Message schedule and all 64 rounds for one block of a SHA-256 hash.
    pub fn sha256_trace(message: &[u8], block_index: usize) -> Result<JsValue> {
        serde_wasm_bindgen::to_value(&trace(message, block_index)?).map_err(|e| CryptoError::new(e.to_string()))
    }

    /// Forge `H(secret ‖ message ‖ padding ‖ suffix)` from `H(secret ‖ message)`.
    pub fn length_extension(digest_hex: &str, secret_len: u32, message: &[u8], suffix: &[u8], secret: &[u8]) -> Result<JsValue> {
        serde_wasm_bindgen::to_value(&length_extension(digest_hex, secret_len as u64, message, suffix, secret)?)
            .map_err(|e| CryptoError::new(e.to_string()))
    }

    /// SHA-256 of `secret ‖ message` — the naive keyed hash the attack breaks.
    pub fn naive_keyed_hash(secret: &[u8], message: &[u8]) -> String {
        let mut input = secret.to_vec();
        input.extend_from_slice(message);
        hex::encode(sha256(&input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn reference(data: &[u8]) -> String {
        hex::encode(sha2::Sha256::digest(data))
    }

    #[test]
    fn matches_the_sha2_crate_and_fips_vectors() {
        assert_eq!(hex::encode(sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex::encode(sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        // Multi-block inputs, including the exact padding boundaries.
        for len in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 128, 1000] {
            let data = vec![0x61u8; len];
            assert_eq!(hex::encode(sha256(&data)), reference(&data), "length {len}");
        }
    }

    #[test]
    fn trace_reproduces_the_digest() {
        let t = trace(b"abc", 0).unwrap();
        assert_eq!(t.block_count, 1);
        assert_eq!(t.rounds.len(), 64);
        assert_eq!(t.schedule.len(), 64);
        // First 16 schedule words are the block itself: "abc" + 0x80 padding.
        assert_eq!(t.schedule[0], "61626380");
        assert_eq!(t.state_in[0], "6a09e667");
        // Concatenated output state is the digest.
        assert_eq!(t.state_out.concat(), t.digest);
        assert_eq!(t.digest, reference(b"abc"));
        // A two-block message exposes a second, non-initial chaining value.
        let long = vec![0x61u8; 100];
        let t2 = trace(&long, 1).unwrap();
        assert_eq!(t2.block_count, 2);
        assert_ne!(t2.state_in[0], "6a09e667");
        assert_eq!(t2.state_out.concat(), reference(&long));
        assert!(trace(b"abc", 5).is_err());
    }

    #[test]
    fn padding_follows_fips_180_4() {
        assert_eq!(padding_for(0).len(), 64);
        assert_eq!(padding_for(3).len(), 61);
        assert_eq!(padding_for(55).len(), 9);
        assert_eq!(padding_for(56).len(), 72); // only 8 bytes left, so it spills into a second block
        assert_eq!(padding_for(64).len(), 64);
        assert_eq!(padding_for(3)[0], 0x80);
        assert_eq!(&padding_for(3)[53..], &24u64.to_be_bytes()); // 3 bytes = 24 bits
    }

    #[test]
    fn length_extension_forges_a_valid_digest_without_the_secret() {
        let secret = b"super-secret-key";
        let message = b"user=alice&role=user";
        let suffix = b"&role=admin";
        let known = HashInternals::naive_keyed_hash(secret, message);

        let att = length_extension(&known, secret.len() as u64, message, suffix, secret).unwrap();
        assert!(att.attack_succeeded);
        assert_eq!(att.forged_digest, att.genuine_digest);
        // The forgery is a real digest of the extended message.
        let mut full = secret.to_vec();
        full.extend_from_slice(&hex::decode(&att.forged_message_hex).unwrap());
        assert_eq!(att.forged_digest, reference(&full));
        // Works for any secret length, which the attacker guesses.
        for len in [1usize, 8, 31, 32, 55, 56, 64] {
            let s = vec![0x41u8; len];
            let d = HashInternals::naive_keyed_hash(&s, message);
            assert!(length_extension(&d, len as u64, message, suffix, &s).unwrap().attack_succeeded, "secret length {len}");
        }
        // A wrong guess at the secret length does not forge anything.
        let wrong = length_extension(&known, secret.len() as u64 + 1, message, suffix, secret).unwrap();
        assert!(!wrong.attack_succeeded);
        assert!(length_extension("00ff", 4, message, suffix, secret).is_err());
    }

    #[test]
    fn hmac_is_not_vulnerable_to_the_same_trick() {
        // The attack recovers the state of a bare hash; HMAC's outer hash means
        // the tag is not the internal state of the message hash.
        let secret = b"super-secret-key";
        let message = b"user=alice";
        let naive = HashInternals::naive_keyed_hash(secret, message);
        let hmac = crate::hashing::hmac_bytes("sha256", secret, message).unwrap();
        assert_ne!(naive, hex::encode(&hmac));
        let att = length_extension(&hex::encode(&hmac), secret.len() as u64, message, b"&admin=1", secret).unwrap();
        assert!(!att.attack_succeeded);
    }
}
