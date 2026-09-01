//! AES-128 with a variable number of rounds, so the effect of each round can
//! be seen rather than described.
//!
//! The `aes` crate used everywhere else fixes the round count at 10, which is
//! the whole point of the standard — so this is a separate implementation.
//! Its correctness gate is that at 10 rounds it reproduces FIPS-197 exactly.

use crate::{CryptoError, Result};
use wasm_bindgen::prelude::*;

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// The full AES-128 key schedule: 11 round keys of 16 bytes.
fn expand_key(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        w[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
    }
    for i in 4..44 {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            t.rotate_left(1);
            for b in t.iter_mut() { *b = SBOX[*b as usize]; }
            t[0] ^= RCON[i / 4];
        }
        for j in 0..4 { w[i][j] = w[i - 4][j] ^ t[j]; }
    }
    let mut keys = [[0u8; 16]; 11];
    for r in 0..11 {
        for c in 0..4 {
            keys[r][c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
        }
    }
    keys
}

fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1b } else { 0 }
}

fn sub_bytes(s: &mut [u8; 16]) {
    for b in s.iter_mut() { *b = SBOX[*b as usize]; }
}

/// The state is column-major, so row r of the state is bytes r, r+4, r+8, r+12.
fn shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    for r in 1..4 {
        for c in 0..4 {
            s[r + 4 * c] = t[r + 4 * ((c + r) % 4)];
        }
    }
}

fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let col = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
        s[4 * c]     = xtime(col[0]) ^ (xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3];
        s[4 * c + 1] = col[0] ^ xtime(col[1]) ^ (xtime(col[2]) ^ col[2]) ^ col[3];
        s[4 * c + 2] = col[0] ^ col[1] ^ xtime(col[2]) ^ (xtime(col[3]) ^ col[3]);
        s[4 * c + 3] = (xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ xtime(col[3]);
    }
}

fn add_round_key(s: &mut [u8; 16], k: &[u8; 16]) {
    for i in 0..16 { s[i] ^= k[i]; }
}

/// Encrypts one block with `rounds` rounds. At `rounds = 10` this is AES-128;
/// fewer rounds is a weakened cipher, which is exactly the point.
pub fn encrypt_block_rounds(key: &[u8; 16], block: &[u8; 16], rounds: u8) -> [u8; 16] {
    let keys = expand_key(key);
    let r = rounds.clamp(1, 10) as usize;
    let mut s = *block;
    add_round_key(&mut s, &keys[0]);
    for round_key in keys.iter().take(r).skip(1) {
        sub_bytes(&mut s);
        shift_rows(&mut s);
        mix_columns(&mut s);
        add_round_key(&mut s, round_key);
    }
    // The last round omits MixColumns, so that decryption is symmetric.
    sub_bytes(&mut s);
    shift_rows(&mut s);
    add_round_key(&mut s, &keys[r]);
    s
}

/// Encrypts a buffer in ECB with a reduced round count. ECB is deliberate: it
/// keeps each block independent so the image shows the cipher's diffusion
/// alone, with no chaining to hide behind.
pub fn encrypt_buffer_rounds(key: &[u8], data: &[u8], rounds: u8) -> Result<Vec<u8>> {
    let key: [u8; 16] = key.try_into().map_err(|_| CryptoError::new("Key must be 16 bytes"))?;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        if chunk.len() == 16 {
            let b: [u8; 16] = chunk.try_into().unwrap();
            out.extend_from_slice(&encrypt_block_rounds(&key, &b, rounds));
        } else {
            out.extend_from_slice(chunk);
        }
    }
    Ok(out)
}

#[wasm_bindgen]
pub struct AesRounds;

#[wasm_bindgen]
impl AesRounds {
    /// ECB-encrypts `data` with AES-128 cut short at `rounds` rounds.
    pub fn encrypt(key: &[u8], data: &[u8], rounds: u8) -> Result<Vec<u8>> {
        encrypt_buffer_rounds(key, data, rounds)
    }

    /// Fraction of output bits that change when one input bit is flipped —
    /// the avalanche, measured per round count.
    pub fn avalanche(key: &[u8], rounds: u8) -> Result<f64> {
        let key: [u8; 16] = key.try_into().map_err(|_| CryptoError::new("Key must be 16 bytes"))?;
        let base = [0u8; 16];
        let a = encrypt_block_rounds(&key, &base, rounds);
        let mut total = 0u32;
        for bit in 0..128 {
            let mut b = base;
            b[bit / 8] ^= 1 << (bit % 8);
            let c = encrypt_block_rounds(&key, &b, rounds);
            total += a.iter().zip(c.iter()).map(|(x, y)| (x ^ y).count_ones()).sum::<u32>();
        }
        Ok(total as f64 / (128.0 * 128.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};

    #[test]
    fn ten_rounds_is_aes_128() {
        // FIPS-197 Appendix C.1.
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let pt = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let out = encrypt_block_rounds(&key.clone().try_into().unwrap(), &pt.clone().try_into().unwrap(), 10);
        assert_eq!(hex::encode(out), "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    #[test]
    fn agrees_with_the_aes_crate_on_random_blocks() {
        // Ten rounds must match the audited implementation for any input.
        let mut key = [0u8; 16];
        let mut block = [0u8; 16];
        for i in 0..64u8 {
            for j in 0..16 {
                key[j] = i.wrapping_mul(7).wrapping_add(j as u8);
                block[j] = i.wrapping_mul(13).wrapping_add((j * 3) as u8);
            }
            let mine = encrypt_block_rounds(&key, &block, 10);
            let cipher = aes::Aes128::new(GenericArray::from_slice(&key));
            let mut theirs = GenericArray::clone_from_slice(&block);
            cipher.encrypt_block(&mut theirs);
            assert_eq!(mine, theirs.as_slice(), "mismatch at iteration {i}");
        }
    }

    #[test]
    fn avalanche_grows_with_rounds_and_saturates() {
        let key = [0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let a1 = AesRounds::avalanche(&key, 1).unwrap();
        let a2 = AesRounds::avalanche(&key, 2).unwrap();
        let a4 = AesRounds::avalanche(&key, 4).unwrap();
        let a10 = AesRounds::avalanche(&key, 10).unwrap();
        // One round barely diffuses: a flipped bit touches only a few output bits.
        assert!(a1 < 0.10, "one round avalanche = {a1}");
        // By four rounds every bit depends on every other, and it stays there.
        assert!(a4 > 0.45 && a4 < 0.55, "four round avalanche = {a4}");
        assert!(a10 > 0.45 && a10 < 0.55, "ten round avalanche = {a10}");
        assert!(a2 > a1, "avalanche must increase from 1 to 2 rounds");
        assert!(AesRounds::avalanche(&[0u8; 8], 10).is_err());
    }

    #[test]
    fn fewer_rounds_leave_structure_behind() {
        // Two identical blocks of flat colour, as an image would have.
        let key = [0x42u8; 16];
        let flat = vec![0xc0u8; 64];
        let one = encrypt_buffer_rounds(&key, &flat, 1).unwrap();
        // ECB means identical input blocks give identical output blocks at any
        // round count — the leak the image demo shows.
        assert_eq!(one[..16], one[16..32]);
        // A partial trailing block is passed through rather than padded.
        let odd = encrypt_buffer_rounds(&key, &[1, 2, 3], 10).unwrap();
        assert_eq!(odd, vec![1, 2, 3]);
    }
}
