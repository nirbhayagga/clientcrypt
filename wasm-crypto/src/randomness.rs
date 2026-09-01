//! Telling random from random-looking.
//!
//! Statistical tests from NIST SP 800-22, a deliberately weak linear
//! congruential generator to fail them, and the extractor/conditioner steps
//! that turn raw physical noise into usable key material.
//!
//! Passing these tests does not make a generator secure — a counter encrypted
//! under AES passes everything here and is perfectly predictable to anyone who
//! knows the key. The tests only catch generators that are *obviously* broken.

use crate::{CryptoError, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

/// Complementary error function, Abramowitz & Stegun 7.1.26 (|error| < 1.5e-7).
/// Used for the p-values below; std has no erfc.
pub fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let ans = t * (-z * z - 1.26551223
        + t * (1.00002368
        + t * (0.37409196
        + t * (0.09678418
        + t * (-0.18628806
        + t * (0.27886807
        + t * (-1.13520398
        + t * (1.48851587
        + t * (-0.82215223
        + t * 0.17087277))))))))).exp();
    if x >= 0.0 { ans } else { 2.0 - ans }
}

fn bits_of(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for i in (0..8).rev() {
            out.push((b >> i) & 1);
        }
    }
    out
}

#[derive(Serialize)]
pub struct Analysis {
    pub bytes: usize,
    pub bits: usize,
    pub ones_fraction: f64,
    /// SP 800-22 §2.1. p < 0.01 means "not random" at the 1% level.
    pub monobit_p: f64,
    /// SP 800-22 §2.3, testing oscillation rather than balance.
    pub runs_p: f64,
    pub runs_observed: usize,
    /// Shannon entropy of the byte distribution, out of 8 bits per byte.
    pub shannon_bits_per_byte: f64,
    /// Chi-squared of the byte histogram against uniform (255 d.o.f.).
    pub chi_squared: f64,
    pub longest_run_of_ones: usize,
    pub distinct_bytes: usize,
}

/// Runs every test on one sample.
pub fn analyse(bytes: &[u8]) -> Result<Analysis> {
    if bytes.is_empty() {
        return Err(CryptoError::new("Need at least one byte to analyse"));
    }
    let bits = bits_of(bytes);
    let n = bits.len() as f64;
    let ones = bits.iter().filter(|&&b| b == 1).count();
    let pi = ones as f64 / n;

    // Monobit: how far the ±1 sum strays from zero.
    let s = (2.0 * ones as f64) - n;
    let monobit_p = erfc(s.abs() / (n * 2.0).sqrt());

    // Runs: how often the bit flips. Only meaningful once the balance is sane.
    let transitions = bits.windows(2).filter(|w| w[0] != w[1]).count();
    let runs_observed = transitions + 1;
    let runs_p = if (pi - 0.5).abs() >= 2.0 / n.sqrt() {
        0.0
    } else {
        let num = (runs_observed as f64 - 2.0 * n * pi * (1.0 - pi)).abs();
        let den = 2.0 * (2.0 * n).sqrt() * pi * (1.0 - pi);
        erfc(num / den)
    };

    let mut longest = 0usize;
    let mut current = 0usize;
    for &b in &bits {
        if b == 1 { current += 1; longest = longest.max(current); } else { current = 0; }
    }

    let mut counts = [0usize; 256];
    for &b in bytes { counts[b as usize] += 1; }
    let expected = bytes.len() as f64 / 256.0;
    let chi_squared = counts.iter().map(|&c| (c as f64 - expected).powi(2) / expected).sum();
    let shannon = counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / bytes.len() as f64;
        -p * p.log2()
    }).sum();

    Ok(Analysis {
        bytes: bytes.len(),
        bits: bits.len(),
        ones_fraction: pi,
        monobit_p,
        runs_p,
        runs_observed,
        shannon_bits_per_byte: shannon,
        chi_squared,
        longest_run_of_ones: longest,
        distinct_bytes: counts.iter().filter(|&&c| c > 0).count(),
    })
}

/// A linear congruential generator: xₙ₊₁ = (a·xₙ + c) mod m, normalised to
/// [0, 1). The defaults on the page are RANDU (a = 65539, c = 0, m = 2³¹),
/// IBM's 1960s generator whose consecutive triples fall on 15 planes.
pub fn lcg_sequence(seed: u64, a: u64, c: u64, m: u64, n: u32) -> Result<Vec<f64>> {
    if m < 2 { return Err(CryptoError::new("Modulus must be at least 2")); }
    let mut x = seed % m;
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        x = ((a as u128 * x as u128 + c as u128) % m as u128) as u64;
        out.push(x as f64 / m as f64);
    }
    Ok(out)
}

/// Raw LCG state values, so the integer sequence can be checked directly.
pub fn lcg_raw(seed: u64, a: u64, c: u64, m: u64, n: u32) -> Vec<u64> {
    let mut x = seed % m.max(2);
    (0..n).map(|_| { x = ((a as u128 * x as u128 + c as u128) % m.max(2) as u128) as u64; x }).collect()
}

/// Von Neumann extractor: read bits in pairs, emit 0 for 01 and 1 for 10,
/// discard equal pairs. Removes bias from an independent source at the cost of
/// most of the input — the honest way to turn skewed physical noise into fair
/// bits without assuming anything about the amount of entropy present.
pub fn von_neumann(bytes: &[u8]) -> Vec<u8> {
    let bits = bits_of(bytes);
    let mut out_bits = Vec::new();
    for pair in bits.chunks_exact(2) {
        match (pair[0], pair[1]) {
            (0, 1) => out_bits.push(0),
            (1, 0) => out_bits.push(1),
            _ => {}
        }
    }
    out_bits.chunks(8).filter(|c| c.len() == 8)
        .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | b))
        .collect()
}

#[derive(Serialize)]
pub struct Extraction {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub retained_fraction: f64,
    pub extracted_hex: String,
    pub conditioned_hex: String,
    pub before: Analysis,
    pub after: Analysis,
}

/// Von Neumann extraction followed by SHA-256 conditioning, with the sample
/// analysed before and after so the improvement is visible.
pub fn extract_and_condition(bytes: &[u8]) -> Result<Extraction> {
    let extracted = von_neumann(bytes);
    if extracted.is_empty() {
        return Err(CryptoError::new("Not enough varying input to extract a single byte"));
    }
    Ok(Extraction {
        input_bytes: bytes.len(),
        output_bytes: extracted.len(),
        retained_fraction: extracted.len() as f64 / bytes.len() as f64,
        extracted_hex: hex::encode(&extracted),
        conditioned_hex: hex::encode(Sha256::digest(bytes)),
        before: analyse(bytes)?,
        after: analyse(&extracted)?,
    })
}

#[wasm_bindgen]
pub struct Randomness;

#[wasm_bindgen]
impl Randomness {
    /// Statistical test battery for one sample.
    pub fn analyse(bytes: &[u8]) -> Result<JsValue> {
        to_js(&analyse(bytes)?)
    }

    /// LCG output in [0, 1), for plotting consecutive pairs.
    pub fn lcg(seed: u64, a: u64, c: u64, m: u64, n: u32) -> Result<Vec<f64>> {
        lcg_sequence(seed, a, c, m, n)
    }

    /// LCG output as bytes, so the same generator can be fed to the tests.
    pub fn lcg_bytes(seed: u64, a: u64, c: u64, m: u64, n: u32) -> Result<Vec<u8>> {
        Ok(lcg_sequence(seed, a, c, m, n)?.iter().map(|v| (v * 256.0) as u8).collect())
    }

    /// Von Neumann extraction plus SHA-256 conditioning.
    pub fn extract(bytes: &[u8]) -> Result<JsValue> {
        to_js(&extract_and_condition(bytes)?)
    }

    /// A cryptographic stream generator: ChaCha20 keyed by a 32-byte seed,
    /// producing `len` bytes. This is the step every OS RNG performs after
    /// gathering a little real entropy — it stretches the seed into an
    /// unlimited stream that no statistical test can distinguish from random,
    /// yet is fully determined by the seed. `nonce_counter` selects an
    /// independent stream from the same seed (the low 8 bytes of the nonce).
    pub fn csprng_stream(seed_hex: &str, nonce_counter: u64, len: u32) -> Result<String> {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        let seed: [u8; 32] = hex::decode(seed_hex)?.try_into().map_err(|_| CryptoError::new("Seed must be 32 bytes"))?;
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&nonce_counter.to_le_bytes());
        let mut cipher = chacha20::ChaCha20::new(&seed.into(), &nonce.into());
        let mut out = vec![0u8; len.min(1 << 20) as usize];
        cipher.apply_keystream(&mut out);
        Ok(hex::encode(out))
    }
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(|e| CryptoError::new(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erfc_matches_known_values() {
        assert!((erfc(0.0) - 1.0).abs() < 1e-6);
        assert!((erfc(1.0) - 0.157_299_2).abs() < 1e-6);
        assert!((erfc(2.0) - 0.004_677_7).abs() < 1e-6);
        assert!((erfc(-1.0) - 1.842_700_8).abs() < 1e-6);
        assert!(erfc(5.0) < 1e-10);
    }

    #[test]
    fn monobit_rejects_skew_and_accepts_balance() {
        // All zeros: maximally unbalanced, p must be ~0.
        let a = analyse(&[0u8; 64]).unwrap();
        assert_eq!(a.ones_fraction, 0.0);
        assert!(a.monobit_p < 1e-9, "p = {}", a.monobit_p);
        assert_eq!(a.distinct_bytes, 1);
        assert!(a.shannon_bits_per_byte < 0.01);

        // Alternating bits: perfectly balanced, so monobit is happy...
        let alt = analyse(&[0b0101_0101u8; 64]).unwrap();
        assert!((alt.ones_fraction - 0.5).abs() < 1e-9);
        assert!(alt.monobit_p > 0.99);
        // ...but the runs test sees that it never stops oscillating.
        assert!(alt.runs_p < 1e-9, "runs p = {}", alt.runs_p);
    }

    #[test]
    fn a_good_sample_passes_both_tests() {
        // SHA-256 output chained: not a CSPRNG, but statistically clean.
        let mut data = Vec::new();
        let mut block = [0u8; 32];
        for _ in 0..32 {
            block = Sha256::digest(block).into();
            data.extend_from_slice(&block);
        }
        let a = analyse(&data).unwrap();
        assert!(a.monobit_p > 0.01, "monobit p = {}", a.monobit_p);
        assert!(a.runs_p > 0.01, "runs p = {}", a.runs_p);
        assert!(a.shannon_bits_per_byte > 7.0);
        assert!((a.ones_fraction - 0.5).abs() < 0.05);
        assert!(analyse(&[]).is_err());
    }

    #[test]
    fn randu_reproduces_its_published_sequence() {
        // RANDU: x = 65539x mod 2^31, seeded with 1.
        let seq = lcg_raw(1, 65539, 0, 1 << 31, 6);
        assert_eq!(seq, vec![65539, 393225, 1769499, 7077969, 26542323, 95552217]);
        // Normalised output stays in range.
        let unit = lcg_sequence(1, 65539, 0, 1 << 31, 100).unwrap();
        assert!(unit.iter().all(|&v| (0.0..1.0).contains(&v)));
        assert!(lcg_sequence(1, 65539, 0, 1, 10).is_err());
    }

    #[test]
    fn a_counter_passes_every_test_here() {
        // The point of the section: perfectly predictable input, perfect
        // scores. Balanced bits and exactly the expected number of runs.
        let counter: Vec<u8> = (0..4096).map(|i| (i & 0xff) as u8).collect();
        let a = analyse(&counter).unwrap();
        assert!((a.ones_fraction - 0.5).abs() < 1e-12);
        assert!(a.monobit_p > 0.999, "monobit p = {}", a.monobit_p);
        assert!(a.runs_p > 0.999, "runs p = {}", a.runs_p);
        assert_eq!(a.distinct_bytes, 256);
        // Statistical tests cannot see that the next byte is trivially known.
    }

    #[test]
    fn randu_outputs_lie_on_a_lattice() {
        // RANDU's defect is not its histogram — it produces all 256 byte
        // values and passes a naive frequency check. The flaw is structural:
        // every triple satisfies x[n+2] = 6*x[n+1] - 9*x[n] (mod 2^31), which
        // is why consecutive triples fall on only 15 planes in the unit cube.
        const M: i128 = 1 << 31;
        let seq = lcg_raw(1, 65539, 0, 1 << 31, 200);
        for w in seq.windows(3) {
            let (x0, x1, x2) = (w[0] as i128, w[1] as i128, w[2] as i128);
            assert_eq!((6 * x1 - 9 * x0).rem_euclid(M), x2, "lattice relation broken");
        }
        // A byte histogram alone would not catch it.
        let bytes = Randomness::lcg_bytes(1, 65539, 0, 1 << 31, 4096).unwrap();
        assert_eq!(analyse(&bytes).unwrap().distinct_bytes, 256);
    }

    #[test]
    fn a_small_modulus_lcg_repeats_quickly() {
        // Period can never exceed the modulus, so the stream cycles.
        let seq = lcg_raw(1, 75, 74, 2048, 5000);
        let first = &seq[..64];
        let repeat = seq.windows(64).skip(1).position(|w| w == first);
        assert!(repeat.is_some(), "a modulus of 2048 must cycle within 5000 draws");
        assert!(repeat.unwrap() < 2048);
    }

    #[test]
    fn csprng_stream_is_deterministic_and_statistically_clean() {
        let seed = "00".repeat(32);
        // Same seed and nonce → identical stream.
        let a = Randomness::csprng_stream(&seed, 0, 128).unwrap();
        let b = Randomness::csprng_stream(&seed, 0, 128).unwrap();
        assert_eq!(a, b);
        // Different nonce → different stream.
        assert_ne!(a, Randomness::csprng_stream(&seed, 1, 128).unwrap());
        // One bit of seed change → completely different stream.
        let mut seed2 = vec![0u8; 32]; seed2[0] = 1;
        assert_ne!(a, Randomness::csprng_stream(&hex::encode(seed2), 0, 128).unwrap());
        // The output passes the statistical battery.
        let stream = hex::decode(Randomness::csprng_stream(&seed, 0, 8192).unwrap()).unwrap();
        let stats = analyse(&stream).unwrap();
        assert!(stats.monobit_p > 0.01 && stats.runs_p > 0.01);
        assert!(stats.shannon_bits_per_byte > 7.9);
        assert!(Randomness::csprng_stream("00", 0, 16).is_err());
    }

    #[test]
    fn von_neumann_debiases_a_skewed_source() {
        // A source emitting 1 three times out of four: heavily biased.
        let mut biased = Vec::new();
        let mut state = 0x1234_5678u32;
        for _ in 0..4096 {
            let mut byte = 0u8;
            for _ in 0..8 {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let bit = if (state >> 16).is_multiple_of(4) { 0 } else { 1 };
                byte = (byte << 1) | bit;
            }
            biased.push(byte);
        }
        let before = analyse(&biased).unwrap();
        assert!(before.ones_fraction > 0.7, "input bias = {}", before.ones_fraction);

        let e = extract_and_condition(&biased).unwrap();
        // The output is much closer to balanced...
        assert!((e.after.ones_fraction - 0.5).abs() < 0.05, "after = {}", e.after.ones_fraction);
        // ...and the cost is most of the input.
        assert!(e.retained_fraction < 0.5, "retained = {}", e.retained_fraction);
        assert_eq!(e.conditioned_hex.len(), 64);
        // An input with no varying pairs yields nothing to extract.
        assert!(extract_and_condition(&[0u8; 8]).is_err());
    }
}
