
pub type ContentType = u8;

pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: ContentType = 20;
pub const CONTENT_TYPE_ALERT: ContentType = 21;
pub const CONTENT_TYPE_HANDSHAKE: ContentType = 22;
pub const CONTENT_TYPE_APPLICATION_DATA: ContentType = 23;


pub type TlsVersion = u16;

pub const TLS_VERSION_1_2: TlsVersion = 0x0303;
pub const TLS_VERSION_1_3: TlsVersion = 0x0304;

pub const MAX_PAYLOAD_LENGTH: usize = 16640;
