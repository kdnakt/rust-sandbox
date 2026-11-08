
use crate::tls13::common::*;

const SERVER_RANDOM_LENGTH: usize = 32;

#[derive(Debug, Clone)]
pub struct ServerHello {
    pub protocol_version: TlsVersion,
    pub random: [u8; SERVER_RANDOM_LENGTH],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suite: CipherSuite,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<u8>,
}
