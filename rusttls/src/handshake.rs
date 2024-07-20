use crate::record::TlsProtocolVersion;


pub enum TlsHandshake {
    ClientHello(TlsProtocolVersion, [u8; 32])
}

impl TlsHandshake {
    pub fn as_bytes(&mut self) -> Vec<u8> {
        match self {
            Self::ClientHello(version, random) => {
                let mut vec: Vec<u8> = Vec::new();
                vec.push(version.major);
                vec.push(version.minor);
                for i in random.into_iter() {
                    vec.push(*i);
                }
                vec
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello() {
        let protocol_version = TlsProtocolVersion::tls1_2();
        let random: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let mut client_hello = TlsHandshake::ClientHello(protocol_version, random);
        let mut expected = vec![3, 3];
        for i in random.into_iter() {
            expected.push(i);
        }
        assert_eq!(expected, client_hello.as_bytes());
    }

}
