
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
