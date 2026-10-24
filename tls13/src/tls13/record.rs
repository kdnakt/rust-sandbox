
use crate::tls13::common::*;

pub struct TlsPlaintext {
    content_type: ContentType,
    version: TlsVersion,
    length: u16,
    payload: Vec<u8>,
}

impl TlsPlaintext {
    const fn new(content_type: ContentType, payload: Vec<u8>) -> Self {
        let length = payload.len() as u16;
        TlsPlaintext {
            content_type,
            version: TLS_VERSION_1_2,
            length,
            payload,
        }
    }
}
