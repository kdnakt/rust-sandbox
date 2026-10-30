use crate::tls13::bytes::*;
use crate::tls13::common::*;

pub struct Extension {
    pub extension_type: ExtensionType,
    pub payload: Vec<u8>,
}

impl Extension {
    pub fn marshall(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.extension_type.to_be_bytes());
        buffer.extend_from_slice(&with_u16length(&self.payload));
        buffer
    }
}
