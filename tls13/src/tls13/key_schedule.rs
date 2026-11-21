
use aws_lc_rs::hmac;

use crate::tls13::bytes::with_u8length;

pub struct HkdfLabel {
    pub length: u16,
    pub label: String,
    pub context: Vec<u8>,
}

pub fn new_hkdf_label(label: &str, context: Vec<u8>, length: usize) -> HkdfLabel {
    let label = format!("tls13 {}", label);
    HkdfLabel {
        length : length as u16,
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
