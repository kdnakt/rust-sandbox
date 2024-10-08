use crate::record::TlsProtocolVersion;

#[derive(Debug, PartialEq)]
pub enum TlsHandshake {
    ClientHello(
        TlsProtocolVersion,
        [u8; 32],
        [u8; 32],
        Vec<CipherSuite>,
        Vec<Extension>,
    ),
    ServerHello(
        TlsProtocolVersion,
        [u8; 32], // Random
        [u8; 32], // legacy session id echo
        CipherSuite,
        Vec<Extension>,
    ),
}

impl TlsHandshake {
    pub fn as_bytes(&mut self) -> Vec<u8> {
        let handshake = match self {
            Self::ClientHello(version, random, legacy_session_id, cipher_suites, extensions) => {
                let mut vec: Vec<u8> = Vec::new();
                vec.push(version.major);
                vec.push(version.minor);
                for i in random.into_iter() {
                    vec.push(*i);
                }
                vec.push(legacy_session_id.len().try_into().unwrap());
                for i in legacy_session_id.into_iter() {
                    vec.push(*i);
                }
                vec.extend_from_slice(&convert((cipher_suites.len() * 2) as u16));
                for c in cipher_suites.into_iter() {
                    vec.extend_from_slice(&convert(c.clone() as u16));
                }
                // Compression methods
                vec.push(1);
                vec.push(0);

                let mut extensions_data = Vec::new();
                for e in extensions.into_iter() {
                    // Type
                    extensions_data.extend_from_slice(&convert(e.extension_type as u16));
                    // Length
                    extensions_data.extend_from_slice(&convert(e.extension_data.len() as u16));
                    // Value
                    extensions_data.extend_from_slice(&e.extension_data);
                }
                vec.extend_from_slice(&convert(extensions_data.len() as u16));
                vec.extend_from_slice(&extensions_data);
                vec
            }
            _ => panic!("Not implemented"),
        };
        let mut handshake_with_header = Vec::new();
        handshake_with_header.push(match self {
            TlsHandshake::ClientHello(_, _, _, _, _) => 1,
            _ => panic!("Not implemented"),
        });
        handshake_with_header.push(0);
        handshake_with_header.extend_from_slice(&convert(handshake.len() as u16));
        handshake_with_header.extend_from_slice(&handshake);
        handshake_with_header
    }

    pub fn from_bytes(data: Vec<u8>) -> TlsHandshake {
        let handshake_len =
            ((data[1] as usize) << 16) + ((data[2] as usize) << 8) + (data[3] as usize);
        match data[0] {
            1 => {
                let major = data[4];
                let minor = data[5];
                let version = TlsProtocolVersion { major, minor };
                let random = data[6..38].try_into().expect("Failed to read random.");
                let session_id_end = (data[38] + 39) as usize;
                let session_id = data[39..session_id_end]
                    .try_into()
                    .expect("Failed to read session_id");
                let cipher_suites_len =
                    ((data[session_id_end] as usize) << 8) + (data[session_id_end + 1] as usize);
                let mut cipher_suites = Vec::new();
                let cipher_suites_start = session_id_end + 2;
                for i in (cipher_suites_start..(cipher_suites_start + cipher_suites_len)).step_by(2)
                {
                    let raw_cipher_suite = ((data[i] as usize) << 8) + (data[i + 1] as usize);
                    cipher_suites.push(raw_cipher_suite.into());
                }
                let mut extensions = Vec::new();
                let extensions_start =
                    cipher_suites_start + 2 /* compression methods ignored */ + cipher_suites_len;
                let extensions_len = ((data[extensions_start] as usize) << 8)
                    + (data[extensions_start + 1] as usize);
                let mut index = extensions_start + 2;
                let extension_end = index + extensions_len;
                while index < extension_end {
                    let extension_type = ((data[index] as usize) << 8) + (data[index + 1] as usize);
                    let ext_len = ((data[index + 2] as usize) << 8) + (data[index + 3] as usize);
                    let ext_value = data[(index + 4)..(index + 4 + ext_len)].into_iter();
                    extensions.push(Extension::from_bytes(extension_type, ext_value));
                    index += 4 + ext_len;
                }
                TlsHandshake::ClientHello(version, random, session_id, cipher_suites, extensions)
            }
            2 => {
                let major = data[4];
                let minor = data[5];
                let version = TlsProtocolVersion { major, minor };
                let random = data[6..38].try_into().expect("Failed to read random.");
                let session_id_end = (data[38] + 39) as usize;
                let session_id = data[39..session_id_end]
                    .try_into()
                    .expect("Failed to read session_id");
                let cipher_suite = (((data[session_id_end] as usize) << 8)
                    + (data[session_id_end + 1] as usize))
                    .into();
                let mut extensions = Vec::new();
                let extensions_start =
                    session_id_end + 3 /* compression methods ignored */;
                let extensions_len = ((data[extensions_start] as usize) << 8)
                    + (data[extensions_start + 1] as usize);
                let mut index = extensions_start + 2;
                let extension_end = index + extensions_len;
                while index < extension_end {
                    let extension_type = ((data[index] as usize) << 8) + (data[index + 1] as usize);
                    let ext_len = ((data[index + 2] as usize) << 8) + (data[index + 3] as usize);
                    let ext_value = data[(index + 4)..(index + 4 + ext_len)].into_iter();
                    extensions.push(Extension::from_bytes(extension_type, ext_value));
                    index += 4 + ext_len;
                }
                TlsHandshake::ServerHello(version, random, session_id, cipher_suite, extensions)
            }
            _ => panic!("Unexpected Handshake Type"),
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug, PartialEq)]
pub enum CipherSuite {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
}

impl From<CipherSuite> for u8 {
    fn from(v: CipherSuite) -> Self {
        v as u8
    }
}

impl From<usize> for CipherSuite {
    fn from(v: usize) -> Self {
        match v {
            0x1301 => CipherSuite::TLS_AES_128_GCM_SHA256,
            0x1302 => CipherSuite::TLS_AES_256_GCM_SHA384,
            _ => panic!("Unknown cipher suite: {}", v),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub extension_data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ExtensionType {
    ServerName = 0,
    SupportedGroups = 10,
    EcPointFormats = 11,
    SignatureAlgorithms = 13,
    SupportedVersions = 43,
    KeyShare = 51,
}

impl Extension {
    pub fn as_bytes(&mut self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(&convert(self.extension_type as u16));
        vec.extend_from_slice(&convert(self.extension_data.len() as u16));
        vec.append(&mut self.extension_data);
        vec
    }

    pub fn from_bytes(extension_type: usize, data: core::slice::Iter<u8>) -> Extension {
        let t = match extension_type {
            0 => ExtensionType::ServerName,
            0x0a => ExtensionType::SupportedGroups,
            0x0d => ExtensionType::SignatureAlgorithms,
            0x2b => ExtensionType::SupportedVersions,
            0x33 => ExtensionType::KeyShare,
            _ => todo!(),
        };
        Extension {
            extension_type: t,
            extension_data: data.cloned().collect(),
        }
    }

    pub fn server_name(hostname: String) -> Extension {
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

    pub fn server_name_value(e: Extension) -> String {
        if e.extension_data[2] != 0 {
            // DNS Hostname type
            panic!("Unsupported server name type: {}", e.extension_data[2]);
        }
        let raw_data = &e.extension_data[5..];
        let hostname_len = ((e.extension_data[3] as usize) << 8) + e.extension_data[4] as usize;
        if raw_data.len() != hostname_len {
            panic!("Unexpected host name length")
        }
        String::from_utf8_lossy(raw_data).to_string()
    }

    pub fn supported_groups(groups: Vec<SupportedGroup>) -> Extension {
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

    pub fn supported_groups_value(e: Extension) -> Vec<SupportedGroup> {
        let mut res = Vec::new();
        for i in (2..(e.extension_data.len() - 1)).step_by(2) {
            let v = ((e.extension_data[i] as u16) << 8) + (e.extension_data[i + 1] as u16);
            res.push(v.into());
        }
        res
    }

    pub fn signature_algorithms(algorithms: Vec<SignatureAlgorithm>) -> Extension {
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

    pub fn signature_algorithms_value(e: Extension) -> Vec<SignatureAlgorithm> {
        let mut res = Vec::new();
        for i in (2..(e.extension_data.len() - 1)).step_by(2) {
            let v = ((e.extension_data[i] as u16) << 8) + (e.extension_data[i + 1] as u16);
            res.push(v.into());
        }
        res
    }

    pub fn supported_versions() -> Extension {
        let data = vec![2, 3, 4];
        Extension {
            extension_type: ExtensionType::SupportedVersions,
            extension_data: data,
        }
    }

    pub fn supported_versions_value(e: Extension) -> Vec<TlsProtocolVersion> {
        let start = if e.extension_data[0] == 3 {
            // server
            0
        } else {
            // client
            1
        };
        let mut res = Vec::new();
        for i in (start..(e.extension_data.len() - 1)).step_by(2) {
            let major = e.extension_data[i];
            let minor = e.extension_data[i + 1];
            res.push(TlsProtocolVersion { major, minor });
        }
        res
    }

    pub fn key_share_client(group: SupportedGroup, public_key: Vec<u8>) -> Extension {
        let mut data = Vec::new();
        data.push(0);
        data.push(0x24);
        data.extend_from_slice(&convert(group as u16));
        data.extend_from_slice(&convert(public_key.len() as u16));
        data.extend_from_slice(&public_key);
        Extension {
            extension_type: ExtensionType::KeyShare,
            extension_data: data,
        }
    }

    pub fn key_share_server(group: SupportedGroup, public_key: Vec<u8>) -> Extension {
        let mut data = Vec::new();
        data.extend_from_slice(&convert(group as u16));
        data.extend_from_slice(&convert(public_key.len() as u16));
        data.extend_from_slice(&public_key);
        Extension {
            extension_type: ExtensionType::KeyShare,
            extension_data: data,
        }
    }

    pub fn key_share_client_value(&self) -> (SupportedGroup, Vec<u8>) {
        self.key_share_value(2)
    }

    pub fn key_share_server_value(&self) -> (SupportedGroup, Vec<u8>) {
        self.key_share_value(0)
    }

    fn key_share_value(&self, index: usize) -> (SupportedGroup, Vec<u8>) {
        let key_len = ((self.extension_data[index + 2] as usize) << 8)
            + (self.extension_data[index + 3] as usize);
        let group =
            ((self.extension_data[index] as u16) << 8) + (self.extension_data[index + 1] as u16);
        (
            group.into(),
            self.extension_data[(index + 4)..(index + 4 + key_len)].to_vec(),
        )
    }

    pub fn ec_point_formats() -> Extension {
        Extension {
            extension_type: ExtensionType::EcPointFormats,
            extension_data: vec![3, 0, 1, 2],
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SupportedGroup {
    X25519 = 0x001d,
    SECP256R1 = 0x0017,
}

impl From<u16> for SupportedGroup {
    fn from(value: u16) -> Self {
        match value {
            0x001d => SupportedGroup::X25519,
            0x0017 => SupportedGroup::SECP256R1,
            _ => panic!("not implemented: {}", value),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SignatureAlgorithm {
    EcdsaSecp256r1Sha256 = 0x0403,
    Ed25519 = 0x0807,
    RsaPssPssSha256 = 0x0809,
}

impl From<u16> for SignatureAlgorithm {
    fn from(value: u16) -> Self {
        match value {
            0x0403 => SignatureAlgorithm::EcdsaSecp256r1Sha256,
            0x0807 => SignatureAlgorithm::Ed25519,
            0x0809 => SignatureAlgorithm::RsaPssPssSha256,
            _ => panic!("Unknown signature algorithm: {}", value),
        }
    }
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
        let mut expected: Vec<u8> = vec![1, 0, 0, 105, 3, 3];
        for i in random.into_iter() {
            expected.push(i);
        }
        expected.push(legacy_session_id.len().try_into().unwrap());
        for i in legacy_session_id.into_iter() {
            expected.push(i);
        }
        let cipher_suites_length = (cipher_suites.len() * 2) as u16;
        expected.push((cipher_suites_length >> 8) as u8);
        expected.push((cipher_suites_length & 0xFF) as u8);
        for c in cipher_suites.into_iter() {
            expected.extend_from_slice(&convert(c.clone() as u16));
        }
        // Compression methods
        expected.push(1);
        expected.push(0);

        let mut extensions_data = Vec::new();
        for e in extensions.into_iter() {
            let type_length = e.extension_type as u16;
            extensions_data.push((type_length >> 8) as u8);
            extensions_data.push((type_length & 0xff) as u8);
            let data_length = e.extension_data.len() as u16;
            extensions_data.push((data_length >> 8) as u8);
            extensions_data.push((data_length & 0xff) as u8);
            // extend?
            for v in e.extension_data.into_iter() {
                extensions_data.push(v);
            }
        }
        expected.extend_from_slice(&convert(extensions_data.len() as u16));
        expected.extend_from_slice(&extensions_data);

        assert_eq!(expected, client_hello.as_bytes());
    }

    #[test]
    fn client_hello_from_bytes() {
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
        let client_hello = TlsHandshake::ClientHello(
            protocol_version,
            random,
            legacy_session_id,
            cipher_suites.clone(),
            extensions.clone(),
        );
        let mut client_hello_data: Vec<u8> = vec![1, 0, 0, 105, 3, 3];
        for i in random.into_iter() {
            client_hello_data.push(i);
        }
        client_hello_data.push(legacy_session_id.len().try_into().unwrap());
        for i in legacy_session_id.into_iter() {
            client_hello_data.push(i);
        }
        let cipher_suites_length = (cipher_suites.len() * 2) as u16;
        client_hello_data.push((cipher_suites_length >> 8) as u8);
        client_hello_data.push((cipher_suites_length & 0xFF) as u8);
        for c in cipher_suites.into_iter() {
            client_hello_data.extend_from_slice(&convert(c.clone() as u16));
        }
        // Compression methods
        client_hello_data.push(1);
        client_hello_data.push(0);

        let mut extensions_data = Vec::new();
        for e in extensions.into_iter() {
            let type_length = e.extension_type as u16;
            extensions_data.push((type_length >> 8) as u8);
            extensions_data.push((type_length & 0xff) as u8);
            let data_length = e.extension_data.len() as u16;
            extensions_data.push((data_length >> 8) as u8);
            extensions_data.push((data_length & 0xff) as u8);
            // extend?
            for v in e.extension_data.into_iter() {
                extensions_data.push(v);
            }
        }
        client_hello_data.extend_from_slice(&convert(extensions_data.len() as u16));
        client_hello_data.extend_from_slice(&extensions_data);

        assert_eq!(client_hello, TlsHandshake::from_bytes(client_hello_data));
    }

    #[test]
    fn server_name_extension() {
        let hostname = "example.ulfheim.net".to_string();
        let actual = Extension::server_name(hostname.clone());
        // cf: https://tls13.xargs.org/#client-hello/annotated
        let expected = vec![
            0, 0, 0, 0x18, 0, 0x16, 0, 0, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
            0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74,
        ];
        assert_eq!(expected, actual.clone().as_bytes());
        let extension_obj = Extension::from_bytes(0, expected[4..].into_iter());
        assert_eq!(actual, extension_obj);
        assert_eq!(hostname, Extension::server_name_value(extension_obj));
    }

    #[test]
    fn supported_groups() {
        let groups = vec![SupportedGroup::X25519, SupportedGroup::SECP256R1];
        let actual = Extension::supported_groups(groups.clone());
        let expected = vec![0, 0x0a, 0, 6, 0, 4, 0, 0x1d, 0, 0x17];
        assert_eq!(expected, actual.clone().as_bytes());
        let extension = Extension::from_bytes(0x0a as usize, expected[4..].into_iter());
        assert_eq!(actual, extension);
        assert_eq!(groups, Extension::supported_groups_value(extension));
    }

    #[test]
    fn signature_algorithms() {
        let algos = vec![
            SignatureAlgorithm::EcdsaSecp256r1Sha256,
            SignatureAlgorithm::Ed25519,
        ];
        let actual = Extension::signature_algorithms(algos.clone());
        let expected = vec![0, 0x0d, 0, 6, 0, 4, 4, 3, 8, 7];
        assert_eq!(expected, actual.clone().as_bytes());
        let ext = Extension::from_bytes(0x0d, expected[4..].into_iter());
        assert_eq!(actual, ext);
        assert_eq!(algos, Extension::signature_algorithms_value(ext));
    }

    #[test]
    fn supported_versions_client() {
        let actual = Extension::supported_versions();
        let expected = vec![0, 0x2b, 0, 3, 2, 3, 4];
        assert_eq!(expected, actual.clone().as_bytes());
        let ext = Extension::from_bytes(0x2b, expected[4..].into_iter());
        assert_eq!(actual, ext);
        assert_eq!(
            vec![TlsProtocolVersion::tls1_3()],
            Extension::supported_versions_value(ext)
        );
    }

    #[test]
    fn supported_versions_server() {
        let actual = Extension {
            extension_type: ExtensionType::SupportedVersions,
            extension_data: vec![3, 4],
        };
        let expected = vec![0, 0x2b, 0, 2, 3, 4];
        assert_eq!(expected, actual.clone().as_bytes());
        let ext = Extension::from_bytes(0x2b, expected[4..].into_iter());
        assert_eq!(actual, ext);
        assert_eq!(
            vec![TlsProtocolVersion::tls1_3()],
            Extension::supported_versions_value(ext)
        );
    }

    #[test]
    fn key_share() {
        // taken from: https://github.com/briansmith/ring/blob/main/src/ec/curve25519/x25519.rs#L217C26-L222C15
        let public_key = vec![
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        let actual = Extension::key_share_client(SupportedGroup::X25519, public_key.clone());
        let mut expected = vec![0, 0x33, 0, 0x26, 0, 0x24, 0, 0x1d, 0, 0x20];
        expected.extend_from_slice(&public_key);
        assert_eq!(expected, actual.clone().as_bytes());
        let ext = Extension::from_bytes(0x33, expected[4..].into_iter());
        assert_eq!(actual, ext);
        let key_share = ext.key_share_client_value();
        assert_eq!(SupportedGroup::X25519, key_share.0);
        assert_eq!(public_key, key_share.1);
    }

    #[test]
    fn key_share_server_value_test() {
        // taken from: https://github.com/briansmith/ring/blob/main/src/ec/curve25519/x25519.rs#L217C26-L222C15
        let public_key = vec![
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        let actual = Extension::key_share_server(SupportedGroup::X25519, public_key.clone());
        let mut expected = vec![0, 0x33, 0, 0x24, 0, 0x1d, 0, 0x20];
        expected.extend_from_slice(&public_key);
        assert_eq!(expected, actual.clone().as_bytes());
        let ext = Extension::from_bytes(0x33, expected[4..].into_iter());
        assert_eq!(actual, ext);
        let key_share = ext.key_share_server_value();
        assert_eq!(SupportedGroup::X25519, key_share.0);
        assert_eq!(public_key, key_share.1);
    }

    #[test]
    fn ec_point_formats() {
        let mut actual = Extension::ec_point_formats();
        let expected = vec![0, 0xb, 0, 4, 3, 0, 1, 2];
        assert_eq!(expected, actual.as_bytes());
    }
}
