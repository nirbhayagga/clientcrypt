//! Classical (pen-and-paper) ciphers and the statistics used to break them.
//!
//! All ciphers act on ASCII letters only; every other character is passed
//! through unchanged and does not consume key material.

use crate::{CryptoError, Result};
use wasm_bindgen::prelude::*;

/// Relative frequency of A–Z in English prose (percent), from Lewand,
/// *Cryptological Mathematics* (2000). Used for chi-squared scoring.
pub const ENGLISH: [f64; 26] = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
    6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
];

fn shift_char(c: char, shift: u8) -> char {
    if c.is_ascii_alphabetic() {
        let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
        (base + (c as u8 - base + shift % 26) % 26) as char
    } else {
        c
    }
}

fn letters(text: &str) -> Vec<u8> {
    text.bytes().filter(u8::is_ascii_alphabetic).map(|b| b.to_ascii_uppercase() - b'A').collect()
}

fn counts(idx: &[u8]) -> [usize; 26] {
    let mut c = [0usize; 26];
    for &i in idx { c[i as usize] += 1; }
    c
}

/// Chi-squared statistic of a letter distribution against English.
fn chi_squared(idx: &[u8]) -> f64 {
    let n = idx.len() as f64;
    if n == 0.0 { return f64::INFINITY; }
    counts(idx).iter().zip(ENGLISH.iter()).map(|(&o, &e)| {
        let expected = e / 100.0 * n;
        (o as f64 - expected).powi(2) / expected
    }).sum()
}

fn ioc(idx: &[u8]) -> f64 {
    let n = idx.len() as f64;
    if n < 2.0 { return 0.0; }
    counts(idx).iter().map(|&c| (c * c.saturating_sub(1)) as f64).sum::<f64>() / (n * (n - 1.0))
}

fn mod_inverse_26(a: u8) -> Option<u8> {
    (1..26u8).find(|&x| (a as u16 * x as u16) % 26 == 1)
}

#[wasm_bindgen]
pub struct ClassicalCipher;

#[wasm_bindgen]
impl ClassicalCipher {
    pub fn caesar_encrypt(text: &str, shift: u8) -> String {
        text.chars().map(|c| shift_char(c, shift)).collect()
    }

    pub fn caesar_decrypt(text: &str, shift: u8) -> String {
        Self::caesar_encrypt(text, 26 - (shift % 26))
    }

    /// Every decryption for shifts 1..=25, in shift order.
    pub fn caesar_brute_force(text: &str) -> Vec<String> {
        (1..=25).map(|s| Self::caesar_decrypt(text, s)).collect()
    }

    /// Atbash: A↔Z, B↔Y, …; an involution, so it is its own inverse.
    pub fn atbash(text: &str) -> String {
        text.chars().map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                (base + 25 - (c as u8 - base)) as char
            } else { c }
        }).collect()
    }

    /// Affine cipher E(x) = (a·x + b) mod 26; requires gcd(a, 26) = 1.
    pub fn affine_encrypt(text: &str, a: u8, b: u8) -> Result<String> {
        if mod_inverse_26(a % 26).is_none() {
            return Err(CryptoError::new("a must be coprime with 26 (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)"));
        }
        Ok(text.chars().map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let x = (c as u8 - base) as u16;
                (base + ((a as u16 * x + b as u16) % 26) as u8) as char
            } else { c }
        }).collect())
    }

    /// Affine decryption D(y) = a⁻¹·(y − b) mod 26.
    pub fn affine_decrypt(text: &str, a: u8, b: u8) -> Result<String> {
        let inv = mod_inverse_26(a % 26)
            .ok_or_else(|| CryptoError::new("a must be coprime with 26 (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)"))? as i32;
        Ok(text.chars().map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let y = (c as u8 - base) as i32;
                (base + ((inv * (y - b as i32)).rem_euclid(26)) as u8) as char
            } else { c }
        }).collect())
    }

    pub fn vigenere_encrypt(text: &str, key: &str) -> Result<String> {
        Self::vigenere(text, key, false)
    }

    pub fn vigenere_decrypt(text: &str, key: &str) -> Result<String> {
        Self::vigenere(text, key, true)
    }

    fn vigenere(text: &str, key: &str, decrypt: bool) -> Result<String> {
        let key = letters(key);
        if key.is_empty() {
            return Err(CryptoError::new("Key must contain at least one letter"));
        }
        let mut i = 0usize;
        Ok(text.chars().map(|c| {
            if c.is_ascii_alphabetic() {
                let k = key[i % key.len()];
                i += 1;
                shift_char(c, if decrypt { 26 - k } else { k })
            } else { c }
        }).collect())
    }

    /// Percentage frequency of each letter A–Z in `text`.
    pub fn letter_frequencies(text: &str) -> Vec<f64> {
        let idx = letters(text);
        let n = idx.len().max(1) as f64;
        counts(&idx).iter().map(|&c| c as f64 / n * 100.0).collect()
    }

    /// English reference distribution (percent), for charts.
    pub fn english_frequencies() -> Vec<f64> {
        ENGLISH.to_vec()
    }

    /// Index of coincidence Σ nᵢ(nᵢ−1) / N(N−1). ≈0.0667 for English,
    /// ≈0.0385 for uniformly random letters.
    pub fn index_of_coincidence(text: &str) -> f64 {
        ioc(&letters(text))
    }

    /// Chi-squared distance from English letter frequencies (lower is more
    /// English-like). Used to rank Caesar brute-force candidates.
    pub fn chi_squared_english(text: &str) -> f64 {
        chi_squared(&letters(text))
    }

    /// Mean index of coincidence of the columns obtained by splitting the
    /// text into `p` interleaved streams, for p = 1..=max_period. A Vigenère
    /// key length shows up as a peak near 0.066.
    pub fn ioc_by_period(text: &str, max_period: u32) -> Vec<f64> {
        let idx = letters(text);
        (1..=max_period.max(1) as usize).map(|p| {
            let cols: Vec<Vec<u8>> = (0..p).map(|k| idx.iter().skip(k).step_by(p).copied().collect()).collect();
            cols.iter().map(|c| ioc(c)).sum::<f64>() / p as f64
        }).collect()
    }

    /// Recovers a Vigenère key of the given length by choosing, for every
    /// column, the shift whose decryption minimises chi-squared against
    /// English. Works for natural-language plaintext of a few hundred letters.
    pub fn vigenere_recover_key(text: &str, key_len: u32) -> Result<String> {
        let idx = letters(text);
        let p = key_len as usize;
        if p == 0 { return Err(CryptoError::new("Key length must be at least 1")); }
        if idx.len() < p * 5 {
            return Err(CryptoError::new("Not enough letters for that key length (need ≥ 5 per column)"));
        }
        let key: String = (0..p).map(|k| {
            let col: Vec<u8> = idx.iter().skip(k).step_by(p).copied().collect();
            let best = (0..26u8).min_by(|&a, &b| {
                let da: Vec<u8> = col.iter().map(|&c| (c + 26 - a) % 26).collect();
                let db: Vec<u8> = col.iter().map(|&c| (c + 26 - b) % 26).collect();
                chi_squared(&da).partial_cmp(&chi_squared(&db)).unwrap_or(std::cmp::Ordering::Equal)
            }).unwrap_or(0);
            (b'A' + best) as char
        }).collect();
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "It was the best of times, it was the worst of times, it was the age of wisdom, \
        it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the \
        season of Light, it was the season of Darkness, it was the spring of hope, it was the winter of despair, \
        we had everything before us, we had nothing before us, we were all going direct to Heaven, we were all \
        going direct the other way - in short, the period was so far like the present period, that some of its \
        noisiest authorities insisted on its being received, for good or for evil, in the superlative degree of \
        comparison only.";

    #[test]
    fn caesar_roundtrip_and_known_answer() {
        assert_eq!(ClassicalCipher::caesar_encrypt("HELLO, World!", 3), "KHOOR, Zruog!");
        assert_eq!(ClassicalCipher::caesar_decrypt("KHOOR, Zruog!", 3), "HELLO, World!");
        assert_eq!(ClassicalCipher::caesar_encrypt("abc", 26), "abc");
        assert_eq!(ClassicalCipher::caesar_brute_force("KHOOR")[2], "HELLO");
    }

    #[test]
    fn atbash_is_an_involution() {
        assert_eq!(ClassicalCipher::atbash("Hello, World"), "Svool, Dliow");
        assert_eq!(ClassicalCipher::atbash(&ClassicalCipher::atbash(SAMPLE)), SAMPLE);
    }

    #[test]
    fn affine_roundtrip_and_validation() {
        let ct = ClassicalCipher::affine_encrypt("AFFINE CIPHER", 5, 8).unwrap();
        assert_eq!(ct, "IHHWVC SWFRCP");
        assert_eq!(ClassicalCipher::affine_decrypt(&ct, 5, 8).unwrap(), "AFFINE CIPHER");
        assert!(ClassicalCipher::affine_encrypt("x", 2, 0).is_err());
        assert!(ClassicalCipher::affine_decrypt("x", 13, 0).is_err());
    }

    #[test]
    fn vigenere_known_answer() {
        let ct = ClassicalCipher::vigenere_encrypt("ATTACKATDAWN", "LEMON").unwrap();
        assert_eq!(ct, "LXFOPVEFRNHR");
        assert_eq!(ClassicalCipher::vigenere_decrypt(&ct, "lemon").unwrap(), "ATTACKATDAWN");
        assert!(ClassicalCipher::vigenere_encrypt("x", "123").is_err());
    }

    #[test]
    fn statistics_distinguish_english_from_random() {
        let ioc_en = ClassicalCipher::index_of_coincidence(SAMPLE);
        assert!(ioc_en > 0.055 && ioc_en < 0.08, "ioc={ioc_en}");
        let flat: String = (0..2600).map(|i| (b'A' + (i % 26) as u8) as char).collect();
        assert!((ClassicalCipher::index_of_coincidence(&flat) - 1.0 / 26.0).abs() < 0.002);
        assert!(ClassicalCipher::chi_squared_english(SAMPLE) < ClassicalCipher::chi_squared_english(&ClassicalCipher::caesar_encrypt(SAMPLE, 7)));
        let f = ClassicalCipher::letter_frequencies("aab");
        assert!((f[0] - 66.666).abs() < 0.01 && (f[1] - 33.333).abs() < 0.01);
    }

    #[test]
    fn vigenere_key_recovery() {
        let ct = ClassicalCipher::vigenere_encrypt(SAMPLE, "LEMON").unwrap();
        let by_period = ClassicalCipher::ioc_by_period(&ct, 12);
        let best = by_period.iter().enumerate().max_by(|a, b| a.1.partial_cmp(b.1).unwrap()).unwrap().0 + 1;
        assert!(best == 5 || best == 10, "period guess {best}");
        assert_eq!(ClassicalCipher::vigenere_recover_key(&ct, 5).unwrap(), "LEMON");
    }
}
