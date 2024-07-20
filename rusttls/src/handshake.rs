use crate::record::TlsProtocolVersion;


pub enum TlsHandshake {
    ClientHello(TlsProtocolVersion)
}

impl TlsHandshake {
    pub fn as_bytes(&mut self) -> Vec<u8> {
        match self {
            Self::ClientHello(version) => {
                let mut vec: Vec<u8> = Vec::new();
                vec.push(version.major);
                vec.push(version.minor);
                vec
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_legacy_version() {
        let protocol_version = TlsProtocolVersion::tls1_2();
        let mut client_hello = TlsHandshake::ClientHello(protocol_version);
        assert_eq!(vec![3, 3], client_hello.as_bytes());
    }

}
