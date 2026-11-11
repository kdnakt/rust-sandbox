
use crate::tls13::{common::*, extensions::{Extension, unmarshall_extensions}};

const SERVER_RANDOM_LENGTH: usize = 32;

#[derive(Debug, Clone)]
pub struct ServerHello {
    pub protocol_version: TlsVersion,
    pub random: [u8; SERVER_RANDOM_LENGTH],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suite: CipherSuite,
    pub compression_method: u8,
    pub extensions: Vec<Extension>,
}

pub fn unmarshall_server_hello(body: &Vec<u8>) -> Result<ServerHello, &'static str> {
    if body.len() < 38 {
        return Err("Insufficient bytes for ServerHello");
    }

    let protocol_version = u16::from_be_bytes([body[0], body[1]]);
    let mut random = [0u8; SERVER_RANDOM_LENGTH];
    random.copy_from_slice(&body[2..2 + SERVER_RANDOM_LENGTH]);

    let legacy_session_id_length = body[34] as usize;
    if body.len() < 35 + legacy_session_id_length + 2 + 1 {
        return Err("Insufficient bytes for legacy session ID and cipher suite");
    }

    let cipher_suite_start = 35 + legacy_session_id_length;
    let legacy_session_id = body[35..cipher_suite_start].to_vec();
    let cipher_suite = u16::from_be_bytes([
        body[cipher_suite_start],
        body[cipher_suite_start + 1],
    ]);

    let compression_methods_length = body[cipher_suite_start + 2] as usize;
    if body.len() < cipher_suite_start + 3 + compression_methods_length {
        return Err("Insufficient bytes for compression methods");
    }

    let compression_method = body[cipher_suite_start + 3];
    let extensions_start = cipher_suite_start + 4;
    if body.len() < extensions_start {
        return Err("Insufficient bytes for extensions");
    }
    let extensions = body[extensions_start..].to_vec();
    let extensions = unmarshall_extensions(extensions)?;

    Ok(ServerHello {
        protocol_version,
        random,
        legacy_session_id,
        cipher_suite,
        compression_method,
        extensions,
    })
}

impl ServerHello {
    pub fn selected_version(&self) -> Option<TlsVersion> {
        for ext in &self.extensions {
            if ext.extension_type == EXT_SUPPORTED_VERSIONS {
                if ext.payload.len() < 2 {
                    return None;
                }
                let version = u16::from_be_bytes([ext.payload[0], ext.payload[1]]);
                return Some(version);
            }
        }
        None
    }

    pub fn key_share(&self) -> Option<(NamedGroup, Vec<u8>)> {
        for ext in &self.extensions {
            if ext.extension_type == EXT_KEY_SHARE {
                if ext.payload.len() < 4 {
                    continue;
                }
                let group = u16::from_be_bytes([ext.payload[0], ext.payload[1]]);
                let key_exchange_length = u16::from_be_bytes([ext.payload[2], ext.payload[3]]) as usize;
                if ext.payload.len() < 4 + key_exchange_length {
                    continue;
                }
                let key = ext.payload[4..4 + key_exchange_length].to_vec();
                return Some((group, key));
            }
        }
        None
    }
}
