use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct ClassicalCipher;

#[wasm_bindgen]
impl ClassicalCipher {
    #[wasm_bindgen]
    pub fn caesar_encrypt(text: &str, shift: u8) -> String {
        let shift = shift % 26;
        text.chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                    let offset = (c as u8 - base + shift) % 26;
                    (base + offset) as char
                } else {
                    c
                }
            })
            .collect()
    }

    #[wasm_bindgen]
    pub fn caesar_decrypt(text: &str, shift: u8) -> String {
        Self::caesar_encrypt(text, 26 - (shift % 26))
    }

    #[wasm_bindgen]
    pub fn caesar_brute_force(text: &str) -> Vec<String> {
        let mut results = Vec::new();
        for shift in 1..=25 {
            results.push(format!("Shift {}: {}", shift, Self::caesar_decrypt(text, shift)));
        }
        results
    }

    #[wasm_bindgen]
    pub fn vigenere_encrypt(text: &str, key: &str) -> String {
        if key.is_empty() { return text.to_string(); }
        let key_chars: Vec<char> = key.chars().filter(|c| c.is_ascii_alphabetic()).collect();
        if key_chars.is_empty() { return text.to_string(); }

        let mut key_idx = 0;
        text.chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                    let k = key_chars[key_idx % key_chars.len()];
                    let k_base = if k.is_ascii_uppercase() { b'A' } else { b'a' };
                    let shift = k as u8 - k_base;
                    
                    key_idx += 1;
                    
                    let offset = (c as u8 - base + shift) % 26;
                    (base + offset) as char
                } else {
                    c
                }
            })
            .collect()
    }

    #[wasm_bindgen]
    pub fn vigenere_decrypt(text: &str, key: &str) -> String {
        if key.is_empty() { return text.to_string(); }
        let key_chars: Vec<char> = key.chars().filter(|c| c.is_ascii_alphabetic()).collect();
        if key_chars.is_empty() { return text.to_string(); }

        let mut key_idx = 0;
        text.chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                    let k = key_chars[key_idx % key_chars.len()];
                    let k_base = if k.is_ascii_uppercase() { b'A' } else { b'a' };
                    let shift = k as u8 - k_base;
                    
                    key_idx += 1;
                    
                    let offset = (c as u8 - base + 26 - shift) % 26;
                    (base + offset) as char
                } else {
                    c
                }
            })
            .collect()
    }

    #[wasm_bindgen]
    pub fn vigenere_frequency_analysis(text: &str) -> Vec<f64> {
        let mut freqs = vec![0.0f64; 26];
        let mut total = 0.0;
        for c in text.chars() {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                freqs[(c as u8 - base) as usize] += 1.0;
                total += 1.0;
            }
        }
        if total > 0.0 {
            for f in freqs.iter_mut() {
                *f = (*f / total) * 100.0;
            }
        }
        freqs
    }
}
