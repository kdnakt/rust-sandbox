use crate::record::TlsProtocolVersion;

pub enum TlsHandshake {
    ClientHello(TlsProtocolVersion, [u8; 32], [u8; 32], Vec<CipherSuite>),
}

impl TlsHandshake {
    pub fn as_bytes(&mut self) -> Vec<u8> {
        match self {
            Self::ClientHello(version, random, legacy_session_id, cipher_suites) => {
                let mut vec: Vec<u8> = Vec::new();
                vec.push(version.major);
                vec.push(version.minor);
                vec.push(random.len().try_into().unwrap());
                for i in random.into_iter() {
                    vec.push(*i);
                }
                for i in legacy_session_id.into_iter() {
                    vec.push(*i);
                }
                let cipher_suites_length = cipher_suites.len() as u16;
                vec.push((cipher_suites_length >> 8) as u8);
                vec.push((cipher_suites_length & 0xFF) as u8);
                for c in cipher_suites.into_iter() {
                    vec.push(c.clone().into());
                }
                vec
            }
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub enum CipherSuite {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
}

impl From<CipherSuite> for u8 {
    fn from(v: CipherSuite) -> Self {
        v as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello() {
        let protocol_version = TlsProtocolVersion::tls1_2();
        let random: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let legacy_session_id: [u8; 32] = [
            11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
        ];
        let cipher_suites = vec![
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
        ];
        let mut client_hello =
            TlsHandshake::ClientHello(protocol_version, random, legacy_session_id, cipher_suites.clone());
        let mut expected: Vec<u8> = vec![3, 3];
        expected.push(random.len().try_into().unwrap());
        for i in random.into_iter() {
            expected.push(i);
        }
        for i in legacy_session_id.into_iter() {
            expected.push(i);
        }
        let cipher_suites_length = cipher_suites.len() as u16;
        expected.push((cipher_suites_length >> 8) as u8);
        expected.push((cipher_suites_length & 0xFF) as u8);
        for c in cipher_suites.into_iter() {
            expected.push(c.into());
        }

        assert_eq!(expected, client_hello.as_bytes());
    }
}
