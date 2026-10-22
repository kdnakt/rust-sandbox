
type content_type = u8;

pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: content_type = 20;
pub const CONTENT_TYPE_ALERT: content_type = 21;
pub const CONTENT_TYPE_HANDSHAKE: content_type = 22;
pub const CONTENT_TYPE_APPLICATION_DATA: content_type = 23;


type tls_version = u16;

pub const TLS_VERSION_1_3: tls_version = 0x0304;

pub const MAX_PAYLOAD_LENGTH: usize = 16640;
