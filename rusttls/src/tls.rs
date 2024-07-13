#[repr(C)]
pub struct TlsRecord {
    pub content_type: TlsContentType,
    pub protocol_version: TlsProtocolVersion,
}


impl TlsRecord {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const TlsRecord as *const u8,
                std::mem::size_of::<TlsRecord>(),
            )
        }
    }
}

#[repr(u8)]
pub enum TlsContentType {
    Handshake = 22, // 0x16
}

pub struct TlsProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_client_hello() {
        let protocol_version = TlsProtocolVersion { major: 3, minor: 3 };
        let client_hello = TlsRecord {
            content_type: TlsContentType::Handshake,
            protocol_version
        };
        assert_eq!([22, 3, 3], client_hello.as_bytes());
    }

}
