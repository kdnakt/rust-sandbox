use crate::tls13::bytes::*;
use crate::tls13::common::*;
use crate::tls13::extensions::*;

const CLIENT_RANDOM_LENGTH: usize = 32;

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub protocol_version: TlsVersion,
    pub client_random: [u8; CLIENT_RANDOM_LENGTH],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

pub fn new_client_hello(random: [u8; CLIENT_RANDOM_LENGTH], extensions: Vec<Extension>) -> ClientHello {
    ClientHello {
        protocol_version: TLS_VERSION_1_2,
        client_random: random,
        legacy_session_id: Vec::new(),
        cipher_suites: vec![TLS_AES_128_GCM_SHA256],
        compression_methods: vec![0], // No compression
        extensions,
    }
}

impl ClientHello {
    pub fn marshall(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.protocol_version.to_be_bytes());
        buffer.extend_from_slice(&self.client_random);
        buffer.extend_from_slice(&with_u8length(&self.legacy_session_id));

        let cipher_suites_bytes: Vec<u8> = self
            .cipher_suites
            .iter()
            .flat_map(|suite| suite.to_be_bytes())
            .collect();
        buffer.extend_from_slice(&with_u16length(&cipher_suites_bytes));

        buffer.extend_from_slice(&with_u8length(&self.compression_methods));
        let extensions_bytes: Vec<u8> = self
            .extensions
            .iter()
            .flat_map(|ext| ext.marshall())
            .collect();
        buffer.extend_from_slice(&with_u16length(&extensions_bytes));
        buffer
    }
}
