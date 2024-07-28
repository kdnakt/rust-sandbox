use crate::record::TlsProtocolVersion;

pub enum TlsHandshake {
    ClientHello(
        TlsProtocolVersion,
        [u8; 32],
        [u8; 32],
        Vec<CipherSuite>,
        Vec<Extension>,
    ),
}

impl TlsHandshake {
    pub fn as_bytes(&mut self) -> Vec<u8> {
        match self {
            Self::ClientHello(version, random, legacy_session_id, cipher_suites, extensions) => {
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
                // Compression methods
                vec.push(1);
                vec.push(0);
                let extension_length = extensions.len() as u16;
                vec.push((extension_length >> 8) as u8);
                vec.push((extension_length & 0xff) as u8);
                for e in extensions.into_iter() {
                    let type_length = e.extension_type.clone() as u16;
                    vec.push((type_length >> 8) as u8);
                    vec.push((type_length & 0xff) as u8);
                    let data_length = e.extension_data.len() as u16;
                    vec.push((data_length >> 8) as u8);
                    vec.push((data_length & 0xff) as u8);
                    for v in e.extension_data.clone().into_iter() {
                        vec.push(v);
                    }
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

#[derive(Clone)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub extension_data: Vec<u8>,
}

#[derive(Clone, Copy)]
pub enum ExtensionType {
    ServerName = 0,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    SupportedVersions = 43,
    KeyShare = 51,
}

impl Extension {
    fn as_bytes(&mut self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(&convert(self.extension_type as u16));
        vec.extend_from_slice(&convert(self.extension_data.len() as u16));
        vec.append(&mut self.extension_data);
        vec
    }

    fn server_name(hostname: String) -> Extension {
        let mut data = Vec::new();
        let hostname_len = hostname.len() as u16;
        let list_len = hostname_len + 3;
        data.extend_from_slice(&convert(list_len));
        data.push(0); // DNS Hostname type
        data.extend_from_slice(&convert(hostname_len));
        for h in hostname.as_bytes() {
            data.push(*h);
        }
        Extension {
            extension_type: ExtensionType::ServerName,
            extension_data: data,
        }
    }

    fn supported_groups(groups: Vec<SupportedGroup>) -> Extension {
        let mut data = Vec::new();
        data.extend_from_slice(&convert((groups.len() * 2) as u16));
        for g in groups {
            data.extend_from_slice(&convert(g as u16));
        }
        Extension {
            extension_type: ExtensionType::SupportedGroups,
            extension_data: data,
        }
    }

    fn signature_algorithms(algorithms: Vec<SignatureAlgorithm>) -> Extension {
        let mut data = Vec::new();
        data.extend_from_slice(&convert((algorithms.len() * 2) as u16));
        for a in algorithms {
            data.extend_from_slice(&convert(a as u16));
        }
        Extension {
            extension_type: ExtensionType::SignatureAlgorithms,
            extension_data: data,
        }
    }

    fn supported_versions() -> Extension {
        let data = vec![2, 3, 4];
        Extension {
            extension_type: ExtensionType::SupportedVersions,
            extension_data: data,
        }
    }

    fn key_share(group: SupportedGroup, public_key: Vec<u8>) -> Extension {
        let mut data = Vec::new();
        data.push(0);
        data.push(0x24);
        data.extend_from_slice(&convert(group as u16));
        data.push(0);
        data.push(0x20);
        data.extend_from_slice(&public_key);
        Extension {
            extension_type: ExtensionType::KeyShare,
            extension_data: data,
        }
    }
}

pub enum SupportedGroup {
    X25519 = 0x001d,
    SECP256R1 = 0x0017,
}

pub enum SignatureAlgorithm {
    EcdsaSecp256r1Sha256 = 0x0403,
    Ed25519 = 0x0807,
    RsaPssPssSha256 = 0x0809,
}

fn convert(num: u16) -> [u8; 2] {
    let lower = (num & 0xff) as u8;
    let upper = (num >> 8) as u8;
    [upper, lower]
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
        let extensions = vec![
            Extension::server_name("localhost".into()),
            Extension::supported_groups(vec![SupportedGroup::X25519, SupportedGroup::SECP256R1]),
        ];
        let mut client_hello = TlsHandshake::ClientHello(
            protocol_version,
            random,
            legacy_session_id,
            cipher_suites.clone(),
            extensions.clone(),
        );
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
        // Compression methods
        expected.push(1);
        expected.push(0);
        let extension_length = extensions.len() as u16;
        expected.push((extension_length >> 8) as u8);
        expected.push((extension_length & 0xff) as u8);
        for e in extensions.into_iter() {
            let type_length = e.extension_type as u16;
            expected.push((type_length >> 8) as u8);
            expected.push((type_length & 0xff) as u8);
            let data_length = e.extension_data.len() as u16;
            expected.push((data_length >> 8) as u8);
            expected.push((data_length & 0xff) as u8);
            for v in e.extension_data.into_iter() {
                expected.push(v);
            }
        }

        assert_eq!(expected, client_hello.as_bytes());
    }

    #[test]
    fn server_name_extension() {
        let mut actual = Extension::server_name("example.ulfheim.net".to_string());
        // cf: https://tls13.xargs.org/#client-hello/annotated
        let expected = vec![
            0, 0, 0, 0x18, 0, 0x16, 0, 0, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
            0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74,
        ];
        assert_eq!(expected, actual.as_bytes());
    }

    #[test]
    fn supported_groups() {
        let mut actual =
            Extension::supported_groups(vec![SupportedGroup::X25519, SupportedGroup::SECP256R1]);
        let expected = vec![0, 0x0a, 0, 6, 0, 4, 0, 0x1d, 0, 0x17];
        assert_eq!(expected, actual.as_bytes());
    }

    #[test]
    fn signature_algorithms() {
        let mut actual = Extension::signature_algorithms(vec![
            SignatureAlgorithm::EcdsaSecp256r1Sha256,
            SignatureAlgorithm::Ed25519,
        ]);
        let expected = vec![0, 0x0d, 0, 6, 0, 4, 4, 3, 8, 7];
        assert_eq!(expected, actual.as_bytes());
    }

    #[test]
    fn supported_versions() {
        let mut actual = Extension::supported_versions();
        let expected = vec![0, 0x2b, 0, 3, 2, 3, 4];
        assert_eq!(expected, actual.as_bytes());
    }

    #[test]
    fn key_share() {
        // taken from: https://github.com/briansmith/ring/blob/main/src/ec/curve25519/x25519.rs#L217C26-L222C15
        let public_key = vec![
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        let mut actual = Extension::key_share(SupportedGroup::X25519, public_key.clone());
        let mut expected = vec![0, 0x33, 0, 0x26, 0, 0x24, 0, 0x1d, 0, 0x20];
        expected.extend_from_slice(&public_key);
        assert_eq!(expected, actual.as_bytes());
    }
}
