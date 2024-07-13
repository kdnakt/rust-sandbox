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

impl TlsContentType {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const TlsContentType as *const u8,
                std::mem::size_of::<TlsContentType>(),
            )
        }
    }
}

pub struct TlsProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl TlsProtocolVersion {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const TlsProtocolVersion as *const u8,
                std::mem::size_of::<TlsProtocolVersion>(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls12() {
        let version = TlsProtocolVersion { major: 3, minor: 3 };
        assert_eq!([3, 3], version.as_bytes());
    }

    #[test]
    fn tls13() {
        let version = TlsProtocolVersion { major: 3, minor: 4 };
        assert_eq!([3, 4], version.as_bytes());
    }
}
