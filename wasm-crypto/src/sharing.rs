//! Shamir secret sharing: split a secret so any k of n shares recover it and
//! any k−1 reveal nothing at all.
//!
//! A random polynomial of degree k−1 with the secret as its constant term is
//! evaluated at x = 1…n; k points determine the polynomial (Lagrange), k−1
//! leave the constant term perfectly undetermined — the same "every secret is
//! consistent with what you hold" argument as the one-time pad in §1.

use crate::{CryptoError, Result};
use rand::Rng;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// The field: arithmetic mod the Mersenne prime 2³¹ − 1 (as in §11).
pub const P: u64 = 2_147_483_647;

fn add(a: u64, b: u64) -> u64 { (a + b) % P }
fn sub(a: u64, b: u64) -> u64 { (a + P - b % P) % P }
fn mul(a: u64, b: u64) -> u64 { (a as u128 * b as u128 % P as u128) as u64 }

fn pow(mut base: u64, mut exp: u64) -> u64 {
    let mut acc = 1;
    base %= P;
    while exp > 0 {
        if exp & 1 == 1 { acc = mul(acc, base); }
        base = mul(base, base);
        exp >>= 1;
    }
    acc
}

// a⁻¹ mod P by Fermat: P is prime.
fn inv(a: u64) -> Result<u64> {
    if a.is_multiple_of(P) {
        return Err(CryptoError::new("Division by zero in the field"));
    }
    Ok(pow(a, P - 2))
}

fn eval(coeffs: &[u64], x: u64) -> u64 {
    // Horner, highest coefficient first when iterated in reverse.
    coeffs.iter().rev().fold(0, |acc, &c| add(mul(acc, x), c))
}

/// Coefficients (constant term first) of the unique degree ≤ points.len()−1
/// polynomial through the given points, by Lagrange in coefficient form.
fn interpolate(points: &[(u64, u64)]) -> Result<Vec<u64>> {
    let k = points.len();
    for (i, (xi, _)) in points.iter().enumerate() {
        for (xj, _) in points.iter().skip(i + 1) {
            if xi % P == xj % P {
                return Err(CryptoError::new("Shares must have distinct x coordinates"));
            }
        }
    }
    let mut coeffs = vec![0u64; k];
    for (i, &(xi, yi)) in points.iter().enumerate() {
        // Basis polynomial ℓ_i(x) = Π_{j≠i} (x − x_j) / (x_i − x_j).
        let mut basis = vec![1u64]; // polynomial "1"
        let mut denom = 1u64;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i == j { continue; }
            // Multiply basis by (x − x_j).
            let mut next = vec![0u64; basis.len() + 1];
            for (d, &c) in basis.iter().enumerate() {
                next[d] = sub(next[d], mul(c, xj));
                next[d + 1] = add(next[d + 1], c);
            }
            basis = next;
            denom = mul(denom, sub(xi, xj));
        }
        let scale = mul(yi, inv(denom)?);
        for (d, &c) in basis.iter().enumerate() {
            coeffs[d] = add(coeffs[d], mul(c, scale));
        }
    }
    Ok(coeffs)
}

fn poly_string(coeffs: &[u64]) -> String {
    let mut parts = vec![coeffs[0].to_string()];
    for (d, &c) in coeffs.iter().enumerate().skip(1) {
        if c == 0 { continue; }
        parts.push(match d {
            1 => format!("{c}·x"),
            _ => format!("{c}·x{}", superscript(d)),
        });
    }
    format!("f(x) = {} (mod {P})", parts.join(" + "))
}

fn superscript(d: usize) -> String {
    const SUP: [char; 10] = ['⁰', '¹', '²', '³', '⁴', '⁵', '⁶', '⁷', '⁸', '⁹'];
    d.to_string().chars().map(|c| SUP[c.to_digit(10).unwrap() as usize]).collect()
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct Share {
    pub x: u32,
    pub y: u32,
}

#[derive(Serialize)]
pub struct ShamirSplit {
    pub secret: u32,
    pub threshold: u32,
    /// The random coefficients above the constant term — normally destroyed
    /// after dealing; shown here because this is a classroom.
    pub coefficients: Vec<u32>,
    pub polynomial: String,
    pub shares: Vec<Share>,
}

pub fn shamir_split(secret: u32, k: u32, n: u32, coeffs_override: Option<Vec<u64>>) -> Result<ShamirSplit> {
    if secret as u64 >= P {
        return Err(CryptoError::new(format!("The secret must be below p = {P}")));
    }
    if !(2..=8).contains(&k) || n < k || n > 10 {
        return Err(CryptoError::new("Need 2 ≤ k ≤ 8 and k ≤ n ≤ 10"));
    }
    let coeffs: Vec<u64> = match coeffs_override {
        Some(c) => {
            if c.len() != (k - 1) as usize || c.iter().any(|&v| v >= P) {
                return Err(CryptoError::new("Need exactly k−1 coefficients below p"));
            }
            c
        }
        None => (1..k).map(|_| OsRng.gen_range(1..P)).collect(),
    };
    let mut all = vec![secret as u64];
    all.extend_from_slice(&coeffs);
    let shares = (1..=n as u64).map(|x| Share { x: x as u32, y: eval(&all, x) as u32 }).collect();
    Ok(ShamirSplit { secret, threshold: k, polynomial: poly_string(&all), coefficients: coeffs.iter().map(|&c| c as u32).collect(), shares })
}

#[derive(Serialize)]
pub struct LagrangeTerm {
    pub x: u32,
    pub y: u32,
    /// ℓ_i(0): the weight this share contributes to the constant term.
    pub weight: u32,
    pub contribution: u32,
}

#[derive(Serialize)]
pub struct ShamirRecon {
    pub secret: u32,
    pub polynomial: String,
    pub terms: Vec<LagrangeTerm>,
}

/// Reconstruct f(0) from any set of shares by Lagrange interpolation.
pub fn shamir_reconstruct(shares: &[Share]) -> Result<ShamirRecon> {
    if shares.len() < 2 {
        return Err(CryptoError::new("Pick at least two shares"));
    }
    let points: Vec<(u64, u64)> = shares.iter().map(|s| (s.x as u64, s.y as u64)).collect();
    let coeffs = interpolate(&points)?;
    let mut terms = Vec::new();
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut weight = 1u64;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                weight = mul(weight, mul(xj, inv(sub(xj, xi))?));
            }
        }
        terms.push(LagrangeTerm { x: xi as u32, y: yi as u32, weight: weight as u32, contribution: mul(yi, weight) as u32 });
    }
    Ok(ShamirRecon { secret: coeffs[0] as u32, polynomial: poly_string(&coeffs), terms })
}

/// The privacy proof, constructively: given k−1 shares and ANY claimed secret,
/// a valid dealing polynomial exists through (0, claim) and those shares.
pub fn shamir_forge(shares: &[Share], claimed_secret: u32) -> Result<ShamirRecon> {
    if claimed_secret as u64 >= P {
        return Err(CryptoError::new(format!("The claimed secret must be below p = {P}")));
    }
    if shares.is_empty() {
        return Err(CryptoError::new("Hold at least one share"));
    }
    let mut points = vec![(0u64, claimed_secret as u64)];
    points.extend(shares.iter().map(|s| (s.x as u64, s.y as u64)));
    let coeffs = interpolate(&points)?;
    Ok(ShamirRecon { secret: coeffs[0] as u32, polynomial: poly_string(&coeffs), terms: vec![] })
}

#[wasm_bindgen]
pub struct Sharing;

#[wasm_bindgen]
impl Sharing {
    pub fn split(secret: u32, k: u32, n: u32) -> Result<JsValue> {
        to_js(&shamir_split(secret, k, n, None)?)
    }

    /// `shares` is [x1, y1, x2, y2, …].
    pub fn reconstruct(shares: &[u32]) -> Result<JsValue> {
        to_js(&shamir_reconstruct(&pairs(shares)?)?)
    }

    pub fn forge(shares: &[u32], claimed_secret: u32) -> Result<JsValue> {
        to_js(&shamir_forge(&pairs(shares)?, claimed_secret)?)
    }
}

fn pairs(flat: &[u32]) -> Result<Vec<Share>> {
    if !flat.len().is_multiple_of(2) {
        return Err(CryptoError::new("Shares come as (x, y) pairs"));
    }
    Ok(flat.chunks(2).map(|c| Share { x: c[0], y: c[1] }).collect())
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(|e| CryptoError::new(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_matches_hand_evaluation_and_any_k_shares_reconstruct() {
        // f(x) = 1234567 + 111x + 222x² mod p: f(1) = 1234900, f(2) = 1235677,
        // f(3) = 1236898, f(4) = 1238563, f(5) = 1240672.
        let s = shamir_split(1234567, 3, 5, Some(vec![111, 222])).unwrap();
        let ys: Vec<u64> = s.shares.iter().map(|sh| sh.y as u64).collect();
        assert_eq!(ys, vec![1234900, 1235677, 1236898, 1238563, 1240672]);
        assert!(s.polynomial.contains("1234567") && s.polynomial.contains("222·x²"));
        // Every 3-subset recovers the secret.
        for subset in [[0usize, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]] {
            let picked: Vec<Share> = subset.iter().map(|&i| s.shares[i]).collect();
            let r = shamir_reconstruct(&picked).unwrap();
            assert_eq!(r.secret, 1234567, "subset {subset:?}");
            // The contributions sum to the secret.
            let total = r.terms.iter().fold(0u64, |a, t| add(a, t.contribution as u64));
            assert_eq!(total, 1234567);
        }
        // More than k shares also work; a corrupted share changes the answer.
        let mut all = s.shares.clone();
        assert_eq!(shamir_reconstruct(&all).unwrap().secret, 1234567);
        all[0].y += 1;
        assert_ne!(shamir_reconstruct(&all).unwrap().secret, 1234567);
    }

    #[test]
    fn k_minus_one_shares_are_consistent_with_every_secret() {
        let s = shamir_split(42, 3, 5, Some(vec![999_999, 123_456])).unwrap();
        let held = &s.shares[0..2]; // one short of the threshold
        for claim in [0u32, 1, 42, 31337, (P - 1) as u32] {
            let forged = shamir_forge(held, claim).unwrap();
            // The forged polynomial really passes through the held shares…
            let coeffs: Vec<u64> = {
                let mut pts = vec![(0, claim as u64)];
                pts.extend(held.iter().map(|sh| (sh.x as u64, sh.y as u64)));
                interpolate(&pts).unwrap()
            };
            for sh in held {
                assert_eq!(eval(&coeffs, sh.x as u64), sh.y as u64);
            }
            // …and has the claimed secret as its constant term.
            assert_eq!(forged.secret, claim);
        }
    }

    #[test]
    fn random_split_round_trips_and_validation_holds() {
        let s = shamir_split(31337, 4, 7, None).unwrap();
        let picked: Vec<Share> = s.shares[2..6].to_vec();
        assert_eq!(shamir_reconstruct(&picked).unwrap().secret, 31337);
        assert!(shamir_split(u32::MAX, 3, 5, None).is_err()); // secret ≥ p
        assert!(shamir_split(1, 1, 5, None).is_err());       // k too small
        assert!(shamir_split(1, 3, 2, None).is_err());       // n < k
        assert!(shamir_reconstruct(&[Share { x: 1, y: 2 }]).is_err());
        assert!(shamir_reconstruct(&[Share { x: 1, y: 2 }, Share { x: 1, y: 3 }]).is_err());
    }
}
