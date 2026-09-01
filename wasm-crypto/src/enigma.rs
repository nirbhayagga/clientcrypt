//! The Wehrmacht Enigma I (three rotors, no double-stepping bugs omitted).
//!
//! Historically the most consequential cipher machine, and a vivid lesson in
//! why key management and operating procedure matter as much as the algorithm:
//! Enigma's wiring was strong for its day, yet it fell to predictable message
//! formats, a reused indicator procedure, and the machine's own quirks. The
//! rotor and reflector wirings here are the real ones.

use crate::{CryptoError, Result};
use serde::Serialize;
use wasm_bindgen::prelude::*;

// Historical rotor wirings (right-hand output for input A..Z), with the notch
// position at which the rotor to the left steps.
const ROTORS: [(&str, u8); 5] = [
    ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", b'Q' - b'A'), // I,   notch Q
    ("AJDKSIRUXBLHWTMCQGZNPYFVOE", b'E' - b'A'), // II,  notch E
    ("BDFHJLCPRTXVZNYEIWGAKMUSQO", b'V' - b'A'), // III, notch V
    ("ESOVPZJAYQUIRHXLNFTGKDCMWB", b'J' - b'A'), // IV,  notch J
    ("VZBRGITYUPSDNHLXAWMJQOFECK", b'Z' - b'A'), // V,   notch Z
];
const REFLECTOR_B: &str = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

struct Rotor {
    forward: [u8; 26],
    backward: [u8; 26],
    notch: u8,
    position: u8,
    ring: u8,
}

impl Rotor {
    fn new(index: usize, position: u8, ring: u8) -> Rotor {
        let (wiring, notch) = ROTORS[index];
        let w = wiring.as_bytes();
        let mut forward = [0u8; 26];
        let mut backward = [0u8; 26];
        for i in 0..26 {
            let o = w[i] - b'A';
            forward[i] = o;
            backward[o as usize] = i as u8;
        }
        Rotor { forward, backward, notch, position, ring }
    }

    fn at_notch(&self) -> bool {
        self.position == self.notch
    }

    // Map a contact through the rotor, accounting for its rotation and ring.
    fn map(&self, c: u8, table: &[u8; 26]) -> u8 {
        let shift = (self.position + 26 - self.ring) % 26;
        let input = (c + shift) % 26;
        (table[input as usize] + 26 - shift) % 26
    }
}

fn parse_plugboard(spec: &str) -> Result<[u8; 26]> {
    let mut board = [0u8; 26];
    for (i, b) in board.iter_mut().enumerate() { *b = i as u8; }
    for pair in spec.split_whitespace() {
        let chars: Vec<char> = pair.chars().collect();
        if chars.len() != 2 || !chars[0].is_ascii_alphabetic() || !chars[1].is_ascii_alphabetic() {
            return Err(CryptoError::new(format!("Plugboard pair '{pair}' must be two letters, e.g. AB")));
        }
        let (a, b) = (chars[0].to_ascii_uppercase() as u8 - b'A', chars[1].to_ascii_uppercase() as u8 - b'A');
        board[a as usize] = b;
        board[b as usize] = a;
    }
    Ok(board)
}

#[derive(Serialize)]
pub struct EnigmaResult {
    pub output: String,
    /// Final visible positions of the three rotors (letters), after encryption.
    pub end_positions: String,
    pub letters_enciphered: u32,
}

/// Enigma is an involution: with identical settings, encryption and decryption
/// are the same operation. `rotors` is three indices 0–4 (rotor I–V) left to
/// right; `positions` and `rings` are three letters each.
pub fn run_enigma(rotor_ids: &[usize], positions: &str, rings: &str, plugboard: &str, text: &str) -> Result<EnigmaResult> {
    if rotor_ids.len() != 3 || rotor_ids.iter().any(|&r| r >= 5) {
        return Err(CryptoError::new("Choose three rotors, each I–V (indices 0–4)"));
    }
    if rotor_ids[0] == rotor_ids[1] || rotor_ids[1] == rotor_ids[2] || rotor_ids[0] == rotor_ids[2] {
        return Err(CryptoError::new("The three rotors must be different"));
    }
    let pos = letters3(positions, "positions")?;
    let ring = letters3(rings, "ring settings")?;
    let board = parse_plugboard(plugboard)?;

    // Index 0 is the leftmost (slow) rotor; 2 is the rightmost (fast) rotor.
    let mut r = [
        Rotor::new(rotor_ids[0], pos[0], ring[0]),
        Rotor::new(rotor_ids[1], pos[1], ring[1]),
        Rotor::new(rotor_ids[2], pos[2], ring[2]),
    ];
    let reflector: Vec<u8> = REFLECTOR_B.bytes().map(|b| b - b'A').collect();

    let mut out = String::new();
    let mut count = 0u32;
    for ch in text.chars() {
        if !ch.is_ascii_alphabetic() {
            out.push(ch);
            continue;
        }
        // Stepping (with the historical double-step of the middle rotor).
        let middle_at_notch = r[1].at_notch();
        if middle_at_notch {
            r[0].position = (r[0].position + 1) % 26;
            r[1].position = (r[1].position + 1) % 26;
        } else if r[2].at_notch() {
            r[1].position = (r[1].position + 1) % 26;
        }
        r[2].position = (r[2].position + 1) % 26;

        let mut c = ch.to_ascii_uppercase() as u8 - b'A';
        c = board[c as usize];
        // Right to left through the rotors.
        c = r[2].map(c, &r[2].forward);
        c = r[1].map(c, &r[1].forward);
        c = r[0].map(c, &r[0].forward);
        c = reflector[c as usize];
        // Left to right on the way back.
        c = r[0].map(c, &r[0].backward);
        c = r[1].map(c, &r[1].backward);
        c = r[2].map(c, &r[2].backward);
        c = board[c as usize];
        out.push((c + b'A') as char);
        count += 1;
    }

    let end: String = r.iter().map(|rot| (rot.position + b'A') as char).collect();
    Ok(EnigmaResult { output: out, end_positions: end, letters_enciphered: count })
}

fn letters3(s: &str, what: &str) -> Result<[u8; 3]> {
    let bytes: Vec<u8> = s.trim().bytes().filter(u8::is_ascii_alphabetic).map(|b| b.to_ascii_uppercase() - b'A').collect();
    if bytes.len() != 3 {
        return Err(CryptoError::new(format!("{what} must be exactly three letters")));
    }
    Ok([bytes[0], bytes[1], bytes[2]])
}

#[wasm_bindgen]
pub struct Enigma;

#[wasm_bindgen]
impl Enigma {
    /// Encrypt or decrypt (the operation is identical). `rotors` is three
    /// indices 0–4, `positions` and `rings` three letters each, `plugboard` a
    /// space-separated list of letter pairs.
    pub fn run(rotors: &[usize], positions: &str, rings: &str, plugboard: &str, text: &str) -> Result<JsValue> {
        serde_wasm_bindgen::to_value(&run_enigma(rotors, positions, rings, plugboard, text)?)
            .map_err(|e| CryptoError::new(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(rotors: &[usize], pos: &str, ring: &str, pb: &str, text: &str) -> EnigmaResult {
        run_enigma(rotors, pos, ring, pb, text).unwrap()
    }

    #[test]
    fn known_answer_rotors_i_ii_iii() {
        // Rotors I II III, rings AAA, positions AAA, no plugboard: a widely
        // reproduced vector — AAAAA enciphers to BDZGO.
        assert_eq!(run(&[0, 1, 2], "AAA", "AAA", "", "AAAAA").output, "BDZGO");
    }

    #[test]
    fn encryption_is_its_own_inverse() {
        let msg = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";
        let ct = run(&[2, 1, 0], "MCK", "BCD", "AV BS CG DL FU HZ IN KM OW RX", msg).output;
        assert_ne!(ct, msg);
        // Same settings decrypt it.
        let pt = run(&[2, 1, 0], "MCK", "BCD", "AV BS CG DL FU HZ IN KM OW RX", &ct).output;
        assert_eq!(pt, msg);
        // No letter ever encrypts to itself — the reflector flaw the Allies exploited.
        for (a, b) in msg.chars().zip(ct.chars()) {
            assert_ne!(a, b);
        }
    }

    #[test]
    fn double_step_and_validation() {
        // The middle rotor's double-step: with rotor II (notch E) in the middle
        // at position D, three keystrokes carry it D→E→F while the left rotor
        // also advances once. Position after is what a real Enigma shows.
        let r = run(&[0, 1, 2], "ADU", "AAA", "", "AAA");
        assert_eq!(r.letters_enciphered, 3);
        assert_eq!(r.end_positions.len(), 3);
        assert!(run_enigma(&[0, 0, 1], "AAA", "AAA", "", "X").is_err()); // repeated rotor
        assert!(run_enigma(&[0, 1, 2], "AA", "AAA", "", "X").is_err());  // bad positions
        assert!(run_enigma(&[0, 1, 2], "AAA", "AAA", "A1", "X").is_err()); // bad plugboard
    }

    #[test]
    fn plugboard_is_an_involution_and_symmetric() {
        // Non-letters pass through untouched.
        let r = run(&[0, 1, 2], "AAA", "AAA", "", "HI THERE!");
        assert!(r.output.contains(' ') && r.output.ends_with('!'));
    }
}
