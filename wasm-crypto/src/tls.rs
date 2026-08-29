//! A TLS 1.3 handshake simulator (RFC 8446): X25519 key share and the HKDF
//! key schedule of §7.1, with AEAD record protection (§5.2) for the derived
//! traffic keys.
//!
//! What is real: the key exchange, every KDF step and label, the traffic key
//! and IV derivation, and record encryption. What is simplified: there are
//! no certificates, signatures or Finished messages, and the "transcript
//! hash" covers a stand-in for the ClientHello/ServerHello bytes rather
//! than real handshake messages.

use crate::{CryptoError, Result};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

const HASH_LEN: usize = 32;

/// HKDF-Extract(salt, ikm) with SHA-256.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec()
}

/// HKDF-Expand-Label(secret, label, context, len) per RFC 8446 §7.1:
/// info = uint16 length ‖ opaque "tls13 " + label ‖ opaque context.
pub fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Result<Vec<u8>> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let hk = Hkdf::<Sha256>::from_prk(secret).map_err(|_| CryptoError::new("PRK must be at least 32 bytes"))?;
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out).map_err(|_| CryptoError::new("Requested length too large"))?;
    Ok(out)
}

/// Derive-Secret(secret, label, messages) = HKDF-Expand-Label(secret, label, H(messages), 32).
pub fn derive_secret(secret: &[u8], label: &str, transcript_hash: &[u8]) -> Result<Vec<u8>> {
    hkdf_expand_label(secret, label, transcript_hash, HASH_LEN)
}

#[derive(Serialize, Default, Clone)]
pub struct Hello {
    pub random: String,
    pub key_share: String,
    pub cipher_suite: String,
    pub group: String,
}

#[derive(Serialize, Default, Clone)]
pub struct KeySchedule {
    pub shared_secret: String,
    pub early_secret: String,
    pub derived_early: String,
    pub handshake_secret: String,
    pub transcript_hash: String,
    pub client_handshake_traffic_secret: String,
    pub server_handshake_traffic_secret: String,
    pub derived_handshake: String,
    pub master_secret: String,
    pub client_application_traffic_secret: String,
    pub server_application_traffic_secret: String,
    pub client_key: String,
    pub client_iv: String,
    pub server_key: String,
    pub server_iv: String,
}

#[derive(Serialize)]
pub struct Record {
    pub sequence: u64,
    pub nonce: String,
    pub header: String,
    pub inner_plaintext: String,
    pub ciphertext: String,
}

#[wasm_bindgen]
pub struct TlsHandshake {
    client_sk: [u8; 32],
    server_sk: [u8; 32],
    client: Hello,
    server: Hello,
    schedule: KeySchedule,
    step: u8,
}

impl Default for TlsHandshake {
    fn default() -> Self { Self::new() }
}

#[wasm_bindgen]
impl TlsHandshake {
    #[wasm_bindgen(constructor)]
    pub fn new() -> TlsHandshake {
        TlsHandshake { client_sk: [0; 32], server_sk: [0; 32], client: Hello::default(), server: Hello::default(), schedule: KeySchedule::default(), step: 0 }
    }

    /// Step 1: the client draws a random and an ephemeral X25519 key share.
    pub fn client_hello(&mut self) -> Result<JsValue> {
        let hello = self.run_client_hello();
        self.to_js(&hello)
    }

    /// Step 2: the server answers with its own random and key share, and both
    /// sides can now run the key schedule.
    pub fn server_hello(&mut self) -> Result<JsValue> {
        let hello = self.run_server_hello()?;
        self.to_js(&hello)
    }

    /// Step 3: the full key schedule of RFC 8446 §7.1 for this handshake.
    pub fn key_schedule(&mut self) -> Result<JsValue> {
        let s = self.run_key_schedule()?;
        self.to_js(&s)
    }

    /// Step 4: protects one application-data record with the client's traffic
    /// key (RFC 8446 §5.2): nonce = IV ⊕ sequence, AAD = 5-byte record header.
    pub fn encrypt_record(&self, plaintext: &[u8], sequence: u64) -> Result<JsValue> {
        let r = self.run_encrypt_record(plaintext, sequence)?;
        self.to_js(&r)
    }

    pub fn step(&self) -> u8 { self.step }

    fn to_js<T: Serialize>(&self, v: &T) -> Result<JsValue> {
        serde_wasm_bindgen::to_value(v).map_err(|e| CryptoError::new(e.to_string()))
    }
}

impl TlsHandshake {
    pub fn run_client_hello(&mut self) -> Hello {
        let mut random = [0u8; 32];
        OsRng.fill_bytes(&mut random);
        OsRng.fill_bytes(&mut self.client_sk);
        let pk = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(self.client_sk));
        self.client = Hello { random: hex::encode(random), key_share: hex::encode(pk.as_bytes()), cipher_suite: "TLS_AES_128_GCM_SHA256 (0x1301)".into(), group: "x25519 (0x001d)".into() };
        self.step = 1;
        self.client.clone()
    }

    pub fn run_server_hello(&mut self) -> Result<Hello> {
        if self.step < 1 { return Err(CryptoError::new("ClientHello must come first")); }
        let mut random = [0u8; 32];
        OsRng.fill_bytes(&mut random);
        OsRng.fill_bytes(&mut self.server_sk);
        let pk = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(self.server_sk));
        self.server = Hello { random: hex::encode(random), key_share: hex::encode(pk.as_bytes()), cipher_suite: self.client.cipher_suite.clone(), group: self.client.group.clone() };
        self.step = 2;
        Ok(self.server.clone())
    }

    pub fn run_key_schedule(&mut self) -> Result<KeySchedule> {
        if self.step < 2 { return Err(CryptoError::new("ServerHello must come first")); }
        let client_pk: [u8; 32] = hex::decode(&self.client.key_share)?.try_into().unwrap();
        let server_pk: [u8; 32] = hex::decode(&self.server.key_share)?.try_into().unwrap();
        let shared = x25519_dalek::StaticSecret::from(self.client_sk).diffie_hellman(&x25519_dalek::PublicKey::from(server_pk));
        let shared_check = x25519_dalek::StaticSecret::from(self.server_sk).diffie_hellman(&x25519_dalek::PublicKey::from(client_pk));
        if shared.as_bytes() != shared_check.as_bytes() { return Err(CryptoError::new("Key shares do not agree")); }

        // Stand-in for H(ClientHello ‖ ServerHello): the fields that would be inside them.
        let mut transcript = Sha256::new();
        transcript.update(hex::decode(&self.client.random)?);
        transcript.update(client_pk);
        transcript.update(hex::decode(&self.server.random)?);
        transcript.update(server_pk);
        let th = transcript.finalize().to_vec();

        self.schedule = schedule_from(shared.as_bytes(), &th)?;
        self.step = 3;
        Ok(self.schedule.clone())
    }

    pub fn run_encrypt_record(&self, plaintext: &[u8], sequence: u64) -> Result<Record> {
        if self.step < 3 { return Err(CryptoError::new("Run the key schedule first")); }
        let key = hex::decode(&self.schedule.client_key)?;
        let iv = hex::decode(&self.schedule.client_iv)?;
        let mut nonce = iv.clone();
        for (i, b) in sequence.to_be_bytes().iter().enumerate() { nonce[4 + i] ^= b; }
        // TLSInnerPlaintext = content ‖ ContentType(application_data = 23)
        let mut inner = plaintext.to_vec();
        inner.push(23);
        let len = inner.len() + 16;
        let header = [0x17, 0x03, 0x03, (len >> 8) as u8, len as u8];
        let ct = crate::block_ciphers::BlockCiphers::aes_gcm_encrypt(&hex::encode(&key), &hex::encode(&nonce), &hex::encode(header), &hex::encode(&inner))?;
        Ok(Record { sequence, nonce: hex::encode(nonce), header: hex::encode(header), inner_plaintext: hex::encode(inner), ciphertext: ct })
    }
}

/// The §7.1 schedule from the (EC)DHE shared secret and transcript hash,
/// without a PSK (so the early secret's IKM is 32 zero bytes).
pub fn schedule_from(shared: &[u8], transcript_hash: &[u8]) -> Result<KeySchedule> {
    let empty_hash = Sha256::digest(b"");
    let early = hkdf_extract(&[0u8; HASH_LEN], &[0u8; HASH_LEN]);
    let derived_early = derive_secret(&early, "derived", &empty_hash)?;
    let handshake = hkdf_extract(&derived_early, shared);
    let c_hs = derive_secret(&handshake, "c hs traffic", transcript_hash)?;
    let s_hs = derive_secret(&handshake, "s hs traffic", transcript_hash)?;
    let derived_hs = derive_secret(&handshake, "derived", &empty_hash)?;
    let master = hkdf_extract(&derived_hs, &[0u8; HASH_LEN]);
    let c_ap = derive_secret(&master, "c ap traffic", transcript_hash)?;
    let s_ap = derive_secret(&master, "s ap traffic", transcript_hash)?;
    Ok(KeySchedule {
        shared_secret: hex::encode(shared),
        early_secret: hex::encode(&early),
        derived_early: hex::encode(&derived_early),
        handshake_secret: hex::encode(&handshake),
        transcript_hash: hex::encode(transcript_hash),
        client_handshake_traffic_secret: hex::encode(&c_hs),
        server_handshake_traffic_secret: hex::encode(&s_hs),
        derived_handshake: hex::encode(&derived_hs),
        master_secret: hex::encode(&master),
        client_key: hex::encode(hkdf_expand_label(&c_ap, "key", &[], 16)?),
        client_iv: hex::encode(hkdf_expand_label(&c_ap, "iv", &[], 12)?),
        server_key: hex::encode(hkdf_expand_label(&s_ap, "key", &[], 16)?),
        server_iv: hex::encode(hkdf_expand_label(&s_ap, "iv", &[], 12)?),
        client_application_traffic_secret: hex::encode(&c_ap),
        server_application_traffic_secret: hex::encode(&s_ap),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> { hex::decode(s).unwrap() }

    #[test]
    fn hkdf_rfc_5869_case_1() {
        let prk = hkdf_extract(&h("000102030405060708090a0b0c"), &h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));
        assert_eq!(hex::encode(&prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let hk = Hkdf::<Sha256>::from_prk(&prk).unwrap();
        let mut okm = [0u8; 42];
        hk.expand(&h("f0f1f2f3f4f5f6f7f8f9"), &mut okm).unwrap();
        assert_eq!(hex::encode(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    #[test]
    fn key_schedule_matches_rfc_8448_simple_handshake() {
        // Ephemeral keys from RFC 8448 §3.
        let client_sk: [u8; 32] = h("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005").try_into().unwrap();
        let server_pk: [u8; 32] = h("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f").try_into().unwrap();
        let shared = x25519_dalek::StaticSecret::from(client_sk).diffie_hellman(&x25519_dalek::PublicKey::from(server_pk));
        assert_eq!(hex::encode(shared.as_bytes()), "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");

        // Transcript hash of the real ClientHello ‖ ServerHello from the trace.
        let th = h("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let s = schedule_from(shared.as_bytes(), &th).unwrap();
        assert_eq!(s.early_secret, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        assert_eq!(s.derived_early, "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        assert_eq!(s.handshake_secret, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
        assert_eq!(s.client_handshake_traffic_secret, "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    }

    #[test]
    fn application_secret_expand_label_matches_rfc_8448() {
        let master = h("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
        let th = h("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
        assert_eq!(hex::encode(derive_secret(&master, "c ap traffic", &th).unwrap()), "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
    }

    #[test]
    fn simulator_runs_end_to_end() {
        let mut hs = TlsHandshake::new();
        assert!(hs.run_server_hello().is_err());
        let c = hs.run_client_hello();
        let sv = hs.run_server_hello().unwrap();
        assert_ne!(c.key_share, sv.key_share);
        let s = hs.run_key_schedule().unwrap();
        assert_eq!(hs.step, 3);
        assert_eq!(s.client_key.len(), 32);
        assert_eq!(s.client_iv.len(), 24);
        assert_ne!(s.client_key, s.server_key);
        let r = hs.run_encrypt_record(b"hello", 1).unwrap();
        assert_eq!(r.header, "1703030016"); // 5 + 1 (type) + 16 (tag) bytes
        assert_eq!(r.ciphertext.len(), (6 + 16) * 2);
        assert_ne!(r.nonce, s.client_iv);
    }
}
