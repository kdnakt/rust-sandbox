use aws_lc_rs::{
    digest::{Context, SHA256},
    hmac,
};

use crate::tls13::bytes::with_u8length;

pub struct HkdfLabel {
    pub length: u16,
    pub label: String,
    pub context: Vec<u8>,
}

pub fn new_hkdf_label(label: &str, context: Vec<u8>, length: usize) -> HkdfLabel {
    let label = format!("tls13 {}", label);
    HkdfLabel {
        length: length as u16,
        label,
        context,
    }
}

impl HkdfLabel {
    pub fn marshall(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.length.to_be_bytes());
        buffer.extend_from_slice(&with_u8length(&self.label.as_bytes().to_vec()));
        buffer.extend_from_slice(&with_u8length(&self.context));
        buffer
    }
}

pub fn hkdf_expand_label(secret: &[u8], label: &str, context: Vec<u8>, length: usize) -> Vec<u8> {
    let hkdf_label = new_hkdf_label(label, context, length);
    let info = hkdf_label.marshall();
    let prk = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let okm = hmac::sign(&prk, &info);
    okm.as_ref()[..length].to_vec()
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let prk = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let okm = hmac::sign(&prk, ikm);
    okm.as_ref().to_vec()
}

pub fn derive_secret(secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
    hkdf_expand_label(secret, label, transcript_hash.to_vec(), 32)
}

pub fn derive_early_secret() -> Vec<u8> {
    let zeros = vec![0u8; 32];
    hkdf_extract(&zeros, &zeros)
}

pub fn derive_handshake_secret(shared_secret: &[u8]) -> Vec<u8> {
    let empty_hash = SHA256.digest(&[]);
    let early_secret = derive_early_secret();
    let salt = derive_secret(&early_secret, "derived", &empty_hash);
    hkdf_extract(&salt, shared_secret)
}

pub fn derive_main_secret(handshake_secret: &[u8]) -> Vec<u8> {
    let empty_hash = SHA256.digest(&[]);
    let salt = derive_secret(handshake_secret, "derived", &empty_hash);
    hkdf_extract(&salt, &[])
}

// Transcript is a struct that holds the hash algorithm
struct Transcript {
    hash: Context,
}

fn new_transcript() -> Transcript {
    Transcript {
        hash: Context::new(&aws_lc_rs::digest::SHA256),
    }
}

impl Transcript {
    fn write(&mut self, data: &[u8]) {
        self.hash.update(data);
    }

    fn sum(&self) -> Vec<u8> {
        let hash_clone = self.hash.clone();
        let digest = hash_clone.finish();
        digest.as_ref().to_vec()
    }
}
