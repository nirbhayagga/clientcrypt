//! The modular arithmetic underneath RSA and Diffie–Hellman, at sizes small
//! enough to follow by hand.
//!
//! Everything here is deliberately toy-sized and *not* secure: the numbers are
//! chosen so every intermediate value fits on screen. The same operations at
//! real sizes are in `asymmetric.rs`.

use crate::{CryptoError, Result};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Multiplication mod `m` via u128, so any modulus below 2^63 is safe.
fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

const MAX: u64 = 1 << 62;

fn check_modulus(m: u64) -> Result<()> {
    if m < 2 {
        return Err(CryptoError::new("Modulus must be at least 2"));
    }
    if m > MAX {
        return Err(CryptoError::new("Keep the modulus below 2^62 so every step stays exact"));
    }
    Ok(())
}

/* Square-and-multiply ------------------------------------------------------ */

#[derive(Serialize)]
pub struct ModExpStep {
    pub bit_index: u32,
    pub bit: u8,
    /// Accumulator after squaring (and multiplying, when the bit is 1).
    pub after_square: String,
    pub after_multiply: String,
    pub multiplied: bool,
}

#[derive(Serialize)]
pub struct ModExpTrace {
    pub base: String,
    pub exponent: String,
    pub modulus: String,
    pub exponent_bits: String,
    pub steps: Vec<ModExpStep>,
    pub result: String,
    /// Multiplications actually performed, versus the naive exponent−1.
    pub multiplications: u32,
    pub naive_multiplications: String,
}

/// Left-to-right binary exponentiation: scan the exponent's bits, squaring the
/// accumulator each time and multiplying by the base when the bit is set.
pub fn mod_exp_trace(base: u64, exponent: u64, modulus: u64) -> Result<ModExpTrace> {
    check_modulus(modulus)?;
    let base_r = base % modulus;
    let bits = if exponent == 0 { String::from("0") } else { format!("{exponent:b}") };
    let mut acc: u64 = 1 % modulus;
    let mut steps = Vec::new();
    let mut mults = 0u32;

    for (i, ch) in bits.chars().enumerate() {
        let bit = if ch == '1' { 1u8 } else { 0 };
        acc = mul_mod(acc, acc, modulus);
        mults += 1;
        let after_square = acc;
        if bit == 1 {
            acc = mul_mod(acc, base_r, modulus);
            mults += 1;
        }
        steps.push(ModExpStep {
            bit_index: i as u32,
            bit,
            after_square: after_square.to_string(),
            after_multiply: acc.to_string(),
            multiplied: bit == 1,
        });
    }
    if exponent == 0 {
        acc = 1 % modulus;
    }

    Ok(ModExpTrace {
        base: base.to_string(),
        exponent: exponent.to_string(),
        modulus: modulus.to_string(),
        exponent_bits: bits,
        steps,
        result: acc.to_string(),
        multiplications: mults,
        naive_multiplications: exponent.saturating_sub(1).to_string(),
    })
}

pub fn mod_exp(base: u64, exponent: u64, modulus: u64) -> u64 {
    let mut acc: u64 = 1 % modulus;
    let mut b = base % modulus;
    let mut e = exponent;
    while e > 0 {
        if e & 1 == 1 {
            acc = mul_mod(acc, b, modulus);
        }
        b = mul_mod(b, b, modulus);
        e >>= 1;
    }
    acc
}

/* Extended Euclid ---------------------------------------------------------- */

#[derive(Serialize)]
pub struct EuclidStep {
    pub a: String,
    pub b: String,
    pub quotient: String,
    pub remainder: String,
    pub s: String,
    pub t: String,
}

#[derive(Serialize)]
pub struct EuclidTrace {
    pub a: String,
    pub b: String,
    pub gcd: String,
    pub x: String,
    pub y: String,
    pub steps: Vec<EuclidStep>,
    /// "a·x + b·y = gcd" with the numbers filled in.
    pub identity: String,
    pub coprime: bool,
    /// a⁻¹ mod b, when it exists.
    pub inverse: Option<String>,
}

/// Extended Euclidean algorithm: gcd(a, b) together with Bézout coefficients
/// x, y satisfying a·x + b·y = gcd(a, b).
pub fn extended_gcd_trace(a: u64, b: u64) -> Result<EuclidTrace> {
    if a == 0 && b == 0 {
        return Err(CryptoError::new("gcd(0, 0) is undefined"));
    }
    let (mut old_r, mut r) = (a as i128, b as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    let (mut old_t, mut t) = (0i128, 1i128);
    let mut steps = Vec::new();

    while r != 0 {
        let q = old_r / r;
        steps.push(EuclidStep {
            a: old_r.to_string(),
            b: r.to_string(),
            quotient: q.to_string(),
            remainder: (old_r - q * r).to_string(),
            s: old_s.to_string(),
            t: old_t.to_string(),
        });
        let nr = old_r - q * r; old_r = r; r = nr;
        let ns = old_s - q * s; old_s = s; s = ns;
        let nt = old_t - q * t; old_t = t; t = nt;
    }

    let gcd = old_r;
    let coprime = gcd == 1;
    let inverse = (coprime && b > 1).then(|| old_s.rem_euclid(b as i128).to_string());

    Ok(EuclidTrace {
        a: a.to_string(),
        b: b.to_string(),
        gcd: gcd.to_string(),
        x: old_s.to_string(),
        y: old_t.to_string(),
        steps,
        identity: format!("{a}·({old_s}) + {b}·({old_t}) = {gcd}"),
        coprime,
        inverse,
    })
}

pub fn mod_inverse(a: u64, m: u64) -> Option<u64> {
    let t = extended_gcd_trace(a % m, m).ok()?;
    t.inverse.and_then(|s| s.parse().ok())
}

fn is_prime(n: u64) -> bool {
    if n < 2 { return false; }
    if n.is_multiple_of(2) { return n == 2; }
    let mut d = 3u64;
    while d.saturating_mul(d) <= n {
        if n.is_multiple_of(d) { return false; }
        d += 2;
    }
    true
}

/* RSA by hand -------------------------------------------------------------- */

#[derive(Serialize)]
pub struct RsaWalkthrough {
    pub p: String,
    pub q: String,
    pub n: String,
    pub phi: String,
    pub lambda: String,
    pub e: String,
    pub d: String,
    pub key_bits: u32,
    pub message: String,
    pub ciphertext: String,
    pub decrypted: String,
    pub roundtrip_ok: bool,
    pub encrypt_trace: ModExpTrace,
    pub decrypt_trace: ModExpTrace,
    pub inverse_proof: String,
}

/// The full RSA key-generation walkthrough for two small primes.
pub fn rsa_walkthrough(p: u64, q: u64, e: u64, message: u64) -> Result<RsaWalkthrough> {
    if !is_prime(p) { return Err(CryptoError::new(format!("{p} is not prime"))); }
    if !is_prime(q) { return Err(CryptoError::new(format!("{q} is not prime"))); }
    if p == q { return Err(CryptoError::new("p and q must be different primes")); }
    let n = p.checked_mul(q).ok_or_else(|| CryptoError::new("p·q overflows"))?;
    if n > MAX { return Err(CryptoError::new("Keep p·q below 2^62")); }
    let phi = (p - 1) * (q - 1);
    let lambda = (p - 1) / gcd(p - 1, q - 1) * (q - 1); // lcm(p−1, q−1)
    if e <= 1 || e >= phi { return Err(CryptoError::new(format!("e must satisfy 1 < e < φ(n) = {phi}"))); }
    if gcd(e, phi) != 1 { return Err(CryptoError::new(format!("e = {e} is not coprime with φ(n) = {phi}"))); }
    let d = mod_inverse(e, lambda).ok_or_else(|| CryptoError::new("e has no inverse modulo λ(n)"))?;
    if message >= n { return Err(CryptoError::new(format!("The message must be smaller than n = {n}"))); }

    let c = mod_exp(message, e, n);
    let m2 = mod_exp(c, d, n);

    Ok(RsaWalkthrough {
        p: p.to_string(),
        q: q.to_string(),
        n: n.to_string(),
        phi: phi.to_string(),
        lambda: lambda.to_string(),
        e: e.to_string(),
        d: d.to_string(),
        key_bits: 64 - n.leading_zeros(),
        message: message.to_string(),
        ciphertext: c.to_string(),
        decrypted: m2.to_string(),
        roundtrip_ok: m2 == message,
        encrypt_trace: mod_exp_trace(message, e, n)?,
        decrypt_trace: mod_exp_trace(c, d, n)?,
        inverse_proof: format!("{e}·{d} mod {lambda} = {}", mul_mod(e, d, lambda)),
    })
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/* Diffie–Hellman by hand ---------------------------------------------------- */

#[derive(Serialize)]
pub struct DhWalkthrough {
    pub p: String,
    pub g: String,
    pub a: String,
    pub b: String,
    pub public_a: String,
    pub public_b: String,
    pub secret_from_alice: String,
    pub secret_from_bob: String,
    pub agree: bool,
    pub trace_a: ModExpTrace,
    pub trace_b: ModExpTrace,
    /// Every value an eavesdropper can see on the wire.
    pub eavesdropper_sees: Vec<String>,
    /// Exponents an attacker must try to brute-force the discrete log.
    pub brute_force_work: String,
}

pub fn dh_walkthrough(p: u64, g: u64, a: u64, b: u64) -> Result<DhWalkthrough> {
    check_modulus(p)?;
    if !is_prime(p) { return Err(CryptoError::new(format!("{p} is not prime"))); }
    if g < 2 || g >= p { return Err(CryptoError::new(format!("The generator must satisfy 2 ≤ g < p = {p}"))); }
    if a == 0 || b == 0 { return Err(CryptoError::new("Private exponents must be non-zero")); }

    let pub_a = mod_exp(g, a, p);
    let pub_b = mod_exp(g, b, p);
    let s_a = mod_exp(pub_b, a, p);
    let s_b = mod_exp(pub_a, b, p);

    Ok(DhWalkthrough {
        p: p.to_string(),
        g: g.to_string(),
        a: a.to_string(),
        b: b.to_string(),
        public_a: pub_a.to_string(),
        public_b: pub_b.to_string(),
        secret_from_alice: s_a.to_string(),
        secret_from_bob: s_b.to_string(),
        agree: s_a == s_b,
        trace_a: mod_exp_trace(g, a, p)?,
        trace_b: mod_exp_trace(pub_b, a, p)?,
        eavesdropper_sees: vec![
            format!("p = {p}"),
            format!("g = {g}"),
            format!("A = g^a mod p = {pub_a}"),
            format!("B = g^b mod p = {pub_b}"),
        ],
        brute_force_work: format!("at most {} exponents to try", p - 1),
    })
}

#[wasm_bindgen]
pub struct Numbers;

#[wasm_bindgen]
impl Numbers {
    /// Square-and-multiply modular exponentiation, step by step.
    pub fn mod_exp_trace(base: u64, exponent: u64, modulus: u64) -> Result<JsValue> {
        to_js(&mod_exp_trace(base, exponent, modulus)?)
    }

    /// Extended Euclidean algorithm with Bézout coefficients and the inverse.
    pub fn extended_gcd(a: u64, b: u64) -> Result<JsValue> {
        to_js(&extended_gcd_trace(a, b)?)
    }

    /// RSA key generation from two small primes, with a worked encryption.
    pub fn rsa_walkthrough(p: u64, q: u64, e: u64, message: u64) -> Result<JsValue> {
        to_js(&rsa_walkthrough(p, q, e, message)?)
    }

    /// Diffie–Hellman with small honest numbers.
    pub fn dh_walkthrough(p: u64, g: u64, a: u64, b: u64) -> Result<JsValue> {
        to_js(&dh_walkthrough(p, g, a, b)?)
    }

    /// Trial-division primality test, for the small numbers used here.
    pub fn is_small_prime(n: u64) -> bool {
        is_prime(n)
    }

    /// The primes below `limit`, so the walkthroughs can offer real choices.
    pub fn primes_below(limit: u32) -> Vec<u32> {
        (2..limit).filter(|&n| is_prime(n as u64)).collect()
    }
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(|e| CryptoError::new(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn square_and_multiply_matches_direct_computation() {
        // 4^13 mod 497 = 445, the worked example in Applied Cryptography.
        let t = mod_exp_trace(4, 13, 497).unwrap();
        assert_eq!(t.result, "445");
        assert_eq!(t.exponent_bits, "1101");
        assert_eq!(t.steps.len(), 4);
        // Far fewer multiplications than the naive method.
        assert!(t.multiplications < 13);
        assert_eq!(t.naive_multiplications, "12");
        // Edge cases and agreement with the non-traced version.
        assert_eq!(mod_exp_trace(5, 0, 7).unwrap().result, "1");
        assert_eq!(mod_exp_trace(0, 5, 7).unwrap().result, "0");
        for (b, e, m) in [(2u64, 10u64, 1000u64), (7, 128, 13), (123456, 65537, 999983)] {
            assert_eq!(mod_exp_trace(b, e, m).unwrap().result, mod_exp(b, e, m).to_string());
        }
        assert!(mod_exp_trace(2, 3, 1).is_err());
    }

    #[test]
    fn extended_euclid_satisfies_bezout() {
        let t = extended_gcd_trace(240, 46).unwrap();
        assert_eq!(t.gcd, "2");
        // 240·(-9) + 46·(47) = 2
        let (x, y): (i128, i128) = (t.x.parse().unwrap(), t.y.parse().unwrap());
        assert_eq!(240 * x + 46 * y, 2);
        assert!(!t.coprime);
        assert!(t.inverse.is_none());

        // A coprime pair yields a usable modular inverse.
        let t = extended_gcd_trace(17, 3120).unwrap();
        assert_eq!(t.gcd, "1");
        assert!(t.coprime);
        assert_eq!(t.inverse.as_deref(), Some("2753"));
        assert_eq!(mod_inverse(17, 3120), Some(2753));
        assert_eq!(mul_mod(17, 2753, 3120), 1);
        assert_eq!(mod_inverse(4, 8), None);
        assert!(extended_gcd_trace(0, 0).is_err());
    }

    #[test]
    fn rsa_walkthrough_reproduces_the_textbook_example() {
        // The canonical p = 61, q = 53, e = 17 example.
        let r = rsa_walkthrough(61, 53, 17, 65).unwrap();
        assert_eq!(r.n, "3233");
        assert_eq!(r.phi, "3120");
        assert_eq!(r.lambda, "780");
        assert_eq!(r.d, "413"); // inverse of e modulo λ(n)
        assert_eq!(r.ciphertext, "2790");
        assert_eq!(r.decrypted, "65");
        assert!(r.roundtrip_ok);
        assert_eq!(r.encrypt_trace.result, "2790");
        assert_eq!(r.decrypt_trace.result, "65");

        // Every message below n survives the round trip.
        for m in [0u64, 1, 2, 100, 3232] {
            assert!(rsa_walkthrough(61, 53, 17, m).unwrap().roundtrip_ok, "message {m}");
        }
        // Validation.
        assert!(rsa_walkthrough(60, 53, 17, 65).is_err());       // p not prime
        assert!(rsa_walkthrough(61, 61, 17, 65).is_err());       // p == q
        assert!(rsa_walkthrough(61, 53, 13, 65).is_err());       // gcd(e, φ) ≠ 1 (13 | 3120)
        assert!(rsa_walkthrough(61, 53, 17, 99999).is_err());    // message ≥ n
    }

    #[test]
    fn diffie_hellman_walkthrough_agrees() {
        // The classic p = 23, g = 5, a = 6, b = 15 example.
        let d = dh_walkthrough(23, 5, 6, 15).unwrap();
        assert_eq!(d.public_a, "8");
        assert_eq!(d.public_b, "19");
        assert_eq!(d.secret_from_alice, "2");
        assert_eq!(d.secret_from_bob, "2");
        assert!(d.agree);
        assert_eq!(d.eavesdropper_sees.len(), 4);
        // Larger honest numbers still agree.
        let d = dh_walkthrough(999983, 7, 12345, 54321).unwrap();
        assert!(d.agree);
        assert!(dh_walkthrough(24, 5, 6, 15).is_err()); // p not prime
        assert!(dh_walkthrough(23, 1, 6, 15).is_err()); // g out of range
        assert!(dh_walkthrough(23, 5, 0, 15).is_err()); // zero exponent
    }

    #[test]
    fn small_prime_helpers() {
        assert!(Numbers::is_small_prime(2));
        assert!(Numbers::is_small_prime(999983));
        assert!(!Numbers::is_small_prime(1));
        assert!(!Numbers::is_small_prime(999981));
        let p = Numbers::primes_below(30);
        assert_eq!(p, vec![2, 3, 5, 7, 11, 13, 17, 19, 23, 29]);
    }
}
