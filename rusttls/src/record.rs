#[repr(C)]
pub struct TlsRecord {
    pub content_type: TlsContentType,
    /// legacy_protocol_version
    pub protocol_version: TlsProtocolVersion,
    pub length: u16,
    pub data: Vec<u8>,
}

impl TlsRecord {
    pub fn new(
        content_type: TlsContentType,
        protocol_version: TlsProtocolVersion,
        data: Vec<u8>,
    ) -> Self {
        Self {
            content_type,
            protocol_version,
            length: data.len() as u16,
            data,
        }
    }

    pub fn as_bytes(&mut self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.push(self.content_type.into());
        vec.push(self.protocol_version.major);
        vec.push(self.protocol_version.minor);
        let len = self.data.len() as u16;
        vec.push((len >> 8) as u8);
        vec.push((len & 0xFF) as u8);
        vec.append(&mut self.data);
        vec
        // unsafe {
        //     std::slice::from_raw_parts(
        //         self as *const TlsRecord as *const u8,
        //         (5 + self.length).into(),
        //         // std::mem::size_of::<TlsRecord>(),
        //     )
        // }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum TlsContentType {
    Handshake = 22, // 0x16
    ChangeCipherSpec = 20,
}

impl From<TlsContentType> for u8 {
    fn from(v: TlsContentType) -> Self {
        v as u8
    }
}

#[derive(Debug, PartialEq)]
pub struct TlsProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl TlsProtocolVersion {
    pub fn tls1_0() -> Self {
        TlsProtocolVersion { major: 3, minor: 1 }
    }
    pub fn tls1_2() -> Self {
        TlsProtocolVersion { major: 3, minor: 3 }
    }
    pub fn tls1_3() -> Self {
        TlsProtocolVersion { major: 3, minor: 4 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_client_hello() {
        let protocol_version = TlsProtocolVersion { major: 3, minor: 3 };
        let data = vec![7, 8, 9];
        let mut client_hello = TlsRecord {
            content_type: TlsContentType::Handshake,
            protocol_version,
            // length: data.len() as u16, // => somehow fails...
            length: 3,
            data,
        };
        assert_eq!(vec![22, 3, 3, 0, 3, 7, 8, 9], client_hello.as_bytes());
    }

    #[test]
    fn new_tls_record() {
        let protocol_version = TlsProtocolVersion { major: 3, minor: 3 };
        let data = vec![7, 8, 9, 10];
        let mut client_hello = TlsRecord::new(TlsContentType::Handshake, protocol_version, data);
        assert_eq!(vec![22, 3, 3, 0, 4, 7, 8, 9, 10], client_hello.as_bytes());
    }
}
