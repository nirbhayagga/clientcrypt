//! Toy elliptic curves over F_p, small enough to see.
//!
//! The same chord-and-tangent group law that powers X25519 and P-256 (§6), on
//! curves y² = x³ + ax + b over a prime field small enough that every point
//! fits on screen and the discrete log can be brute-forced live. Nothing here
//! is secret-safe; the point is to make "point addition" a picture instead of
//! a phrase.

use crate::{CryptoError, Result};
use serde::Serialize;
use wasm_bindgen::prelude::*;

const MAX_P: i64 = 997;

fn is_prime(n: i64) -> bool {
    if n < 2 { return false; }
    let mut d = 2;
    while d * d <= n {
        if n % d == 0 { return false; }
        d += 1;
    }
    true
}

fn norm(v: i64, p: i64) -> i64 {
    ((v % p) + p) % p
}

// a⁻¹ mod p by Fermat (p is prime and a ≢ 0).
fn inv_mod(a: i64, p: i64) -> i64 {
    let mut base = norm(a, p);
    let mut exp = p - 2;
    let mut acc = 1i64;
    while exp > 0 {
        if exp & 1 == 1 { acc = acc * base % p; }
        base = base * base % p;
        exp >>= 1;
    }
    acc
}

#[derive(Clone, Copy, PartialEq, Debug)]
struct Curve { p: i64, a: i64, b: i64 }

/// None is the point at infinity, the group identity.
type Pt = Option<(i64, i64)>;

fn check_curve(p: i64, a: i64, b: i64) -> Result<Curve> {
    if !(3..=MAX_P).contains(&p) || !is_prime(p) {
        return Err(CryptoError::new(format!("p must be a prime between 3 and {MAX_P}")));
    }
    let c = Curve { p, a: norm(a, p), b: norm(b, p) };
    // Non-singular: 4a³ + 27b² ≠ 0 mod p.
    if norm(4 * c.a % p * c.a % p * c.a + 27 * c.b % p * c.b, p) == 0 {
        return Err(CryptoError::new("Singular curve: 4a³ + 27b² ≡ 0 mod p — the group law breaks down"));
    }
    Ok(c)
}

fn on_curve(c: Curve, pt: Pt) -> bool {
    match pt {
        None => true,
        Some((x, y)) => norm(y * y - (x * x % c.p * x + c.a * x + c.b), c.p) == 0,
    }
}

fn add(c: Curve, p1: Pt, p2: Pt) -> (Pt, Option<i64>, &'static str) {
    match (p1, p2) {
        (None, q) => (q, None, "P + O = P"),
        (q, None) => (q, None, "P + O = P"),
        (Some((x1, y1)), Some((x2, y2))) => {
            if x1 == x2 && norm(y1 + y2, c.p) == 0 {
                // Vertical line: the third intersection is at infinity.
                return (None, None, "inverse: P + (−P) = O");
            }
            let s = if x1 == x2 {
                // Tangent at P: s = (3x² + a) / 2y.
                norm(3 * x1 % c.p * x1 + c.a, c.p) * inv_mod(2 * y1, c.p) % c.p
            } else {
                // Chord through P and Q: s = (y2 − y1) / (x2 − x1).
                norm(y2 - y1, c.p) * inv_mod(x2 - x1, c.p) % c.p
            };
            let x3 = norm(s * s - x1 - x2, c.p);
            let y3 = norm(s * (x1 - x3) - y1, c.p);
            (Some((x3, y3)), Some(s), if x1 == x2 { "double: tangent line" } else { "add: chord line" })
        }
    }
}

fn scalar_mult(c: Curve, k: u32, g: Pt) -> Pt {
    let mut acc: Pt = None;
    let mut base = g;
    let mut k = k;
    while k > 0 {
        if k & 1 == 1 { acc = add(c, acc, base).0; }
        base = add(c, base, base).0;
        k >>= 1;
    }
    acc
}

fn parse_point(c: Curve, x: i64, y: i64, what: &str) -> Result<Pt> {
    let pt = Some((norm(x, c.p), norm(y, c.p)));
    if !on_curve(c, pt) {
        return Err(CryptoError::new(format!("{what} ({x}, {y}) is not on the curve")));
    }
    Ok(pt)
}

#[derive(Serialize)]
pub struct EcPoint { pub x: i32, pub y: i32 }

fn ser(pt: Pt) -> Option<EcPoint> {
    pt.map(|(x, y)| EcPoint { x: x as i32, y: y as i32 })
}

#[derive(Serialize)]
pub struct EcAdd {
    pub point: Option<EcPoint>,
    pub slope: Option<i32>,
    pub case: String,
}

pub fn ec_add(p: i64, a: i64, b: i64, x1: i64, y1: i64, x2: i64, y2: i64) -> Result<EcAdd> {
    let c = check_curve(p, a, b)?;
    let p1 = parse_point(c, x1, y1, "P")?;
    let p2 = parse_point(c, x2, y2, "Q")?;
    let (r, slope, case) = add(c, p1, p2);
    Ok(EcAdd { point: ser(r), slope: slope.map(|v| v as i32), case: case.into() })
}

pub fn ec_points(p: i64, a: i64, b: i64) -> Result<Vec<EcPoint>> {
    let c = check_curve(p, a, b)?;
    let mut out = Vec::new();
    for x in 0..c.p {
        for y in 0..c.p {
            if on_curve(c, Some((x, y))) {
                out.push(EcPoint { x: x as i32, y: y as i32 });
            }
        }
    }
    Ok(out)
}

#[derive(Serialize)]
pub struct EcSubgroup {
    /// G, 2G, 3G, … up to (order−1)G — the walk the UI animates.
    pub multiples: Vec<EcPoint>,
    /// Smallest k with kG = O.
    pub order: u32,
    pub curve_points: u32,
}

pub fn ec_subgroup(p: i64, a: i64, b: i64, gx: i64, gy: i64) -> Result<EcSubgroup> {
    let c = check_curve(p, a, b)?;
    let g = parse_point(c, gx, gy, "G")?;
    let mut multiples = Vec::new();
    let mut acc = g;
    while let Some((x, y)) = acc {
        multiples.push(EcPoint { x: x as i32, y: y as i32 });
        if multiples.len() as i64 > 2 * c.p + 2 {
            return Err(CryptoError::new("Subgroup iteration did not terminate"));
        }
        acc = add(c, acc, g).0;
    }
    let order = multiples.len() as u32 + 1; // + the point at infinity
    Ok(EcSubgroup { multiples, order, curve_points: ec_points(p, a, b)?.len() as u32 + 1 })
}

#[derive(Serialize)]
pub struct EcDh {
    pub alice_public: Option<EcPoint>,
    pub bob_public: Option<EcPoint>,
    pub shared_alice: Option<EcPoint>,
    pub shared_bob: Option<EcPoint>,
    pub agree: bool,
    /// Steps a brute-force attacker needed to recover Alice's secret from her
    /// public point.
    pub dlog_steps: u32,
    pub dlog_found: u32,
}

pub fn ec_dh(p: i64, a: i64, b: i64, gx: i64, gy: i64, alice: u32, bob: u32) -> Result<EcDh> {
    let c = check_curve(p, a, b)?;
    let g = parse_point(c, gx, gy, "G")?;
    if alice == 0 || bob == 0 {
        return Err(CryptoError::new("Secrets must be at least 1"));
    }
    let pa = scalar_mult(c, alice, g);
    let pb = scalar_mult(c, bob, g);
    let sa = scalar_mult(c, alice, pb);
    let sb = scalar_mult(c, bob, pa);

    // The attack that keeps toy curves toy: walk G, 2G, 3G, … until Alice's
    // public point appears.
    let mut acc = g;
    let mut steps = 1u32;
    while acc != pa && steps <= 4 * MAX_P as u32 {
        acc = add(c, acc, g).0;
        steps += 1;
    }

    Ok(EcDh {
        alice_public: ser(pa),
        bob_public: ser(pb),
        shared_alice: ser(sa),
        shared_bob: ser(sb),
        agree: sa == sb && sa.is_some(),
        dlog_steps: steps,
        dlog_found: steps,
    })
}

#[derive(Serialize)]
pub struct EcScalarStep {
    pub bit: u8,
    pub op: String,
    pub point: Option<EcPoint>,
}

#[derive(Serialize)]
pub struct EcScalarMult {
    pub result: Option<EcPoint>,
    pub steps: Vec<EcScalarStep>,
}

/// Double-and-add, MSB first, with the trace the UI displays.
pub fn ec_scalar_mult_trace(p: i64, a: i64, b: i64, gx: i64, gy: i64, k: u32) -> Result<EcScalarMult> {
    let c = check_curve(p, a, b)?;
    let g = parse_point(c, gx, gy, "G")?;
    if k == 0 || k > 100_000 {
        return Err(CryptoError::new("k must be between 1 and 100000"));
    }
    let mut steps = Vec::new();
    let mut acc: Pt = None;
    for i in (0..32).rev() {
        if k >> i == 0 { continue; }
        let bit = ((k >> i) & 1) as u8;
        if acc.is_some() {
            acc = add(c, acc, acc).0;
            steps.push(EcScalarStep { bit, op: "double".into(), point: ser(acc) });
        }
        if bit == 1 {
            acc = add(c, acc, g).0;
            steps.push(EcScalarStep { bit, op: if steps.is_empty() { "start with G".into() } else { "add G".into() }, point: ser(acc) });
        }
    }
    Ok(EcScalarMult { result: ser(acc), steps })
}

#[wasm_bindgen]
pub struct Ecc;

#[wasm_bindgen]
impl Ecc {
    pub fn points(p: i32, a: i32, b: i32) -> Result<JsValue> {
        to_js(&ec_points(p.into(), a.into(), b.into())?)
    }
    pub fn add(p: i32, a: i32, b: i32, x1: i32, y1: i32, x2: i32, y2: i32) -> Result<JsValue> {
        to_js(&ec_add(p.into(), a.into(), b.into(), x1.into(), y1.into(), x2.into(), y2.into())?)
    }
    pub fn subgroup(p: i32, a: i32, b: i32, gx: i32, gy: i32) -> Result<JsValue> {
        to_js(&ec_subgroup(p.into(), a.into(), b.into(), gx.into(), gy.into())?)
    }
    pub fn scalar_mult(p: i32, a: i32, b: i32, gx: i32, gy: i32, k: u32) -> Result<JsValue> {
        to_js(&ec_scalar_mult_trace(p.into(), a.into(), b.into(), gx.into(), gy.into(), k)?)
    }
    pub fn dh(p: i32, a: i32, b: i32, gx: i32, gy: i32, alice: u32, bob: u32) -> Result<JsValue> {
        to_js(&ec_dh(p.into(), a.into(), b.into(), gx.into(), gy.into(), alice, bob)?)
    }
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(|e| CryptoError::new(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The textbook curve y² = x³ + 2x + 2 over F_17 with G = (5, 1).
    const C: (i64, i64, i64) = (17, 2, 2);

    #[test]
    fn doubling_matches_the_hand_computation() {
        // At G = (5,1): s = (3·25 + 2)/(2·1) = 77·2⁻¹ = 9·9 = 81 ≡ 13 (mod 17);
        // x3 = 169 − 10 ≡ 6, y3 = 13·(5−6) − 1 ≡ 3. So 2G = (6, 3).
        let r = ec_add(C.0, C.1, C.2, 5, 1, 5, 1).unwrap();
        let pt = r.point.unwrap();
        assert_eq!((pt.x, pt.y, r.slope.unwrap()), (6, 3, 13));
        assert!(r.case.contains("double"));
        // P + (−P) = O: (5,1) + (5,16).
        assert!(ec_add(C.0, C.1, C.2, 5, 1, 5, 16).unwrap().point.is_none());
        // A point off the curve is rejected.
        assert!(ec_add(C.0, C.1, C.2, 5, 2, 5, 1).is_err());
        assert!(check_curve(16, 2, 2).is_err()); // not prime
        assert!(check_curve(5, 0, 0).is_err());  // singular
    }

    #[test]
    fn the_group_has_order_19_and_g_generates_it() {
        // |E(F_17)| = 19 (a prime), so every point except O is a generator.
        assert_eq!(ec_points(C.0, C.1, C.2).unwrap().len(), 18);
        let sg = ec_subgroup(C.0, C.1, C.2, 5, 1).unwrap();
        assert_eq!(sg.order, 19);
        assert_eq!(sg.curve_points, 19);
        assert_eq!(sg.multiples.len(), 18);
        // 19G = O, and the group law is commutative on a sample.
        let c = check_curve(C.0, C.1, C.2).unwrap();
        assert_eq!(scalar_mult(c, 19, Some((5, 1))), None);
        let (p1, p2) = (Some((5, 1)), Some((6, 3)));
        assert_eq!(add(c, p1, p2).0, add(c, p2, p1).0);
        // Associativity on a sample: (G + 2G) + 3G = G + (2G + 3G).
        let g3 = scalar_mult(c, 3, p1);
        assert_eq!(add(c, add(c, p1, p2).0, g3).0, add(c, p1, add(c, p2, g3).0).0);
    }

    #[test]
    fn double_and_add_agrees_with_repeated_addition() {
        let c = check_curve(C.0, C.1, C.2).unwrap();
        let g = Some((5, 1));
        let mut walk: Pt = None;
        for k in 1..=20u32 {
            walk = add(c, walk, g).0;
            let fast = ec_scalar_mult_trace(C.0, C.1, C.2, 5, 1, k).unwrap();
            assert_eq!(fast.result.map(|p| (p.x as i64, p.y as i64)), walk, "k = {k}");
        }
        // The trace for k = 5 (101₂) is: start G, double, double, add G.
        let t = ec_scalar_mult_trace(C.0, C.1, C.2, 5, 1, 5).unwrap();
        assert_eq!(t.steps.len(), 4);
        assert!(ec_scalar_mult_trace(C.0, C.1, C.2, 5, 1, 0).is_err());
    }

    #[test]
    fn ecdh_agrees_and_the_toy_dlog_falls_instantly() {
        let r = ec_dh(C.0, C.1, C.2, 5, 1, 3, 7).unwrap();
        assert!(r.agree);
        // 3·(7G) = 7·(3G) = 21G = 2G = (6, 3).
        let s = r.shared_alice.unwrap();
        assert_eq!((s.x, s.y), (6, 3));
        // Brute force finds Alice's secret in exactly 3 steps: G, 2G, 3G.
        assert_eq!(r.dlog_found, 3);
        assert!(ec_dh(C.0, C.1, C.2, 5, 1, 0, 7).is_err());
        // The largest curve the UI allows still falls instantly — the lesson.
        let g = &ec_points(997, 3, 7).unwrap()[0];
        let big = ec_dh(997, 3, 7, g.x.into(), g.y.into(), 555, 444).unwrap();
        assert!(big.agree);
    }
}
