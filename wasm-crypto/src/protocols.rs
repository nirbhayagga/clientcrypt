//! Applied protocols built from the primitives elsewhere in the crate:
//! WPA2-PSK key derivation (IEEE 802.11i) and HOTP/TOTP one-time passwords
//! (RFC 4226 / RFC 6238). JWT signing on the site reuses `hashing` and
//! `asymmetric` directly and needs nothing extra here.

use crate::{hashing, CryptoError, Result};
use sha1::Sha1;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Protocols;

#[wasm_bindgen]
impl Protocols {
    /// WPA2-PSK pairwise master key: PBKDF2-HMAC-SHA1(passphrase, SSID,
    /// 4096 iterations, 256 bits), per IEEE 802.11i. The SSID is the salt,
    /// which is why precomputed tables only work per network name.
    pub fn wpa2_pmk(passphrase: &str, ssid: &str) -> Result<String> {
        if !(8..=63).contains(&passphrase.len()) {
            return Err(CryptoError::new("WPA2 passphrases are 8–63 characters"));
        }
        if ssid.is_empty() || ssid.len() > 32 {
            return Err(CryptoError::new("SSID must be 1–32 bytes"));
        }
        let mut pmk = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), ssid.as_bytes(), 4096, &mut pmk);
        Ok(hex::encode(pmk))
    }

    /// HOTP (RFC 4226): dynamic truncation of HMAC(secret, counter) to
    /// `digits` decimal digits. `alg` is sha1 (the standard), sha256 or sha512.
    pub fn hotp(secret: &[u8], counter: u64, digits: u32, alg: &str) -> Result<String> {
        if !(6..=8).contains(&digits) {
            return Err(CryptoError::new("Digits must be 6–8"));
        }
        let mac = hashing::hmac_bytes(alg, secret, &counter.to_be_bytes())?;
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes(mac[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        Ok(format!("{:0width$}", bin % 10u32.pow(digits), width = digits as usize))
    }

    /// TOTP (RFC 6238): HOTP with counter = floor(unix_time / step).
    pub fn totp(secret: &[u8], unix_time: u64, step: u32, digits: u32, alg: &str) -> Result<String> {
        if step == 0 {
            return Err(CryptoError::new("Step must be ≥ 1 second"));
        }
        Self::hotp(secret, unix_time / step as u64, digits, alg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wpa2_pmk_ieee_802_11i_vectors() {
        assert_eq!(Protocols::wpa2_pmk("password", "IEEE").unwrap(),
            "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e");
        assert_eq!(Protocols::wpa2_pmk("ThisIsAPassword", "ThisIsASSID").unwrap(),
            "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af");
        assert!(Protocols::wpa2_pmk("short", "IEEE").is_err());
        assert!(Protocols::wpa2_pmk("longenough", "").is_err());
    }

    #[test]
    fn hotp_rfc_4226_appendix_d() {
        let key = b"12345678901234567890";
        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(&Protocols::hotp(key, counter as u64, 6, "sha1").unwrap(), want);
        }
        assert!(Protocols::hotp(key, 0, 9, "sha1").is_err());
        assert!(Protocols::hotp(key, 0, 6, "md4").is_err());
    }

    #[test]
    fn totp_rfc_6238_appendix_b() {
        let k1 = b"12345678901234567890".as_slice();
        let k256 = b"12345678901234567890123456789012".as_slice();
        let k512 = b"1234567890123456789012345678901234567890123456789012345678901234".as_slice();
        for (t, sha1, sha256, sha512) in [
            (59u64, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ] {
            assert_eq!(Protocols::totp(k1, t, 30, 8, "sha1").unwrap(), sha1);
            assert_eq!(Protocols::totp(k256, t, 30, 8, "sha256").unwrap(), sha256);
            assert_eq!(Protocols::totp(k512, t, 30, 8, "sha512").unwrap(), sha512);
        }
        assert!(Protocols::totp(k1, 59, 0, 8, "sha1").is_err());
    }
}
