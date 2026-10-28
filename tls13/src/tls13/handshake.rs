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

    pub fn marshall(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(self.handshake_type);
        buffer.extend_from_slice(&self.length);
        buffer.extend_from_slice(&self.body);
        buffer
    }
}

fn unmarshall_handshake(bytes: &[u8]) -> Result<Handshake, &'static str> {
    if bytes.len() < 4 {
        return Err("Insufficient bytes for handshake header");
    }
    let handshake_type = bytes[0];
    let length = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
    if bytes.len() != 4 + length as usize {
        return Err("Invalid handshake body length");
    }
    let body = bytes[4..4 + length as usize].to_vec();
    Ok(Handshake {
        handshake_type,
        length: [bytes[1], bytes[2], bytes[3]],
        body,
    })
}
