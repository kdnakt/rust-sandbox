use crate::tls13::common::HandshakeType;

pub struct Handshake {
    pub handshake_type: HandshakeType,
    pub length: [u8; 3],
    pub body: Vec<u8>,
}

impl Handshake {
    pub fn new(handshake_type: HandshakeType, body: Vec<u8>) -> Self {
        let length = (body.len() as u32).to_be_bytes();
        Handshake {
            handshake_type,
            length: [length[1], length[2], length[3]], // Use only the last 3 bytes
            body,
        }
    }
}
