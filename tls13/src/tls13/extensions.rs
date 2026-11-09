use crate::tls13::bytes::*;
use crate::tls13::common::*;

pub struct Extension {
    pub extension_type: ExtensionType,
    pub payload: Vec<u8>,
}

impl Extension {
    pub fn marshall(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.extension_type.to_be_bytes());
        buffer.extend_from_slice(&with_u16length(&self.payload));
        buffer
    }
}

pub fn unmarshall_extensions(data: Vec<u8>) -> Result<Vec<Extension>, &'static str> {
    let mut extensions = Vec::new();
    let mut cursor = 0;

    while cursor < data.len() {
        if cursor + 4 > data.len() {
            return Err("Insufficient bytes for extension header");
        }
        let extension_type = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
        let length = u16::from_be_bytes([data[cursor + 2], data[cursor + 3]]) as usize;
        cursor += 4;

        if cursor + length > data.len() {
            return Err("Insufficient bytes for extension payload");
        }
        let payload = data[cursor..cursor + length].to_vec().clone();
        cursor += length;

        extensions.push(Extension {
            extension_type,
            payload,
        });
    }

    Ok(extensions)
}

pub fn server_name_extension(hostname: &str) -> Extension {
    let hostname_bytes = hostname.as_bytes().to_vec();
    let mut payload = Vec::new();
    payload.push(0); // NameType: host_name
    payload.extend_from_slice(&with_u16length(&hostname_bytes));
    Extension {
        extension_type: EXT_SERVER_NAME,
        payload,
    }
}

pub fn supported_versions_extension() -> Extension {
    let versions = TLS_VERSION_1_3.to_be_bytes().to_vec();
    Extension {
        extension_type: EXT_SUPPORTED_VERSIONS,
        payload: with_u8length(&versions),
    }
}

pub fn signature_algorithms_extension() -> Extension {
    let algorithms = [
        SIG_RSA_PKCS1_SHA256,
        SIG_ECDSA_SECP256R1_SHA256,
        SIG_ECDSA_SECP384R1_SHA384,
        SIG_RSA_PSS_RSAE_SHA256,
        SIG_RSA_PSS_RSAE_SHA384,
        SIG_RSA_PSS_RSAE_SHA512,
    ]
    .iter()
    .map(|a| a.to_be_bytes())
    .flatten()
    .collect::<Vec<u8>>();
    Extension {
        extension_type: EXT_SIGNATURE_ALGORITHMS,
        payload: with_u16length(&algorithms),
    }
}

pub fn supported_groups_extension() -> Extension {
    let groups = [X25519]
        .iter()
        .map(|g| g.to_be_bytes())
        .flatten()
        .collect::<Vec<u8>>();
    Extension {
        extension_type: EXT_SUPPORTED_GROUPS,
        payload: with_u16length(&groups),
    }
}

pub fn key_share_extension(public_key: Vec<u8>) -> Extension {
    let key_share_entry = {
        let mut entry = Vec::new();
        entry.extend_from_slice(&X25519.to_be_bytes());
        entry.extend_from_slice(&with_u16length(&public_key));
        entry
    };
    let payload = with_u16length(&key_share_entry);
    Extension {
        extension_type: EXT_KEY_SHARE,
        payload,
    }
}
