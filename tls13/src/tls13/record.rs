
use crate::tls13::common::*;

pub struct TlsPlaintext {
    content_type: ContentType,
    version: TlsVersion,
    length: u16,
    payload: Vec<u8>,
}

impl TlsPlaintext {
    pub fn new(content_type: ContentType, payload: Vec<u8>) -> Self {
        let length = payload.len() as u16;
        TlsPlaintext {
            content_type,
            version: TLS_VERSION_1_2,
            length,
            payload,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 {
            return None;
        }
        let content_type = bytes[0];
        let version = u16::from_be_bytes([bytes[1], bytes[2]]);
        let length = u16::from_be_bytes([bytes[3], bytes[4]]);
        if bytes.len() < 5 + length as usize {
            return None;
        }
        let payload = bytes[5..5 + length as usize].to_vec();
        Some(TlsPlaintext {
            content_type,
            version,
            length,
            payload,
        })
    }

    pub fn marshall(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(self.content_type);
        buffer.extend_from_slice(&self.version.to_be_bytes());
        buffer.extend_from_slice(&self.length.to_be_bytes());
        buffer.extend_from_slice(&self.payload);
        buffer
    }
}
