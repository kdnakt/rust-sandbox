
pub type ContentType = u8;

pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: ContentType = 20;
pub const CONTENT_TYPE_ALERT: ContentType = 21;
pub const CONTENT_TYPE_HANDSHAKE: ContentType = 22;
pub const CONTENT_TYPE_APPLICATION_DATA: ContentType = 23;


pub type TlsVersion = u16;

pub const TLS_VERSION_1_2: TlsVersion = 0x0303;
pub const TLS_VERSION_1_3: TlsVersion = 0x0304;

pub const MAX_PAYLOAD_LENGTH: usize = 16640;

pub type HandshakeType = u8;

pub const HSTYPE_CLIENT_HELLO: HandshakeType = 1;
pub const HSTYPE_SERVER_HELLO: HandshakeType = 2;
pub const HSTYPE_ENCRYPTED_EXTENSIONS: HandshakeType = 8;
pub const HSTYPE_CERTIFICATE: HandshakeType = 11;
pub const HSTYPE_CERTIFICATE_VERIFY: HandshakeType = 15;
pub const HSTYPE_FINISHED: HandshakeType = 20;

pub type CipherSuite = u16;

pub const TLS_AES_128_GCM_SHA256: CipherSuite = 0x1301;

pub type ExtensionType = u16;

pub const EXT_SERVER_NAME: ExtensionType = 0;
pub const EXT_SUPPORTED_GROUPS: ExtensionType = 10;
pub const EXT_SIGNATURE_ALGORITHMS: ExtensionType = 13;
pub const EXT_SUPPORTED_VERSIONS: ExtensionType = 43;
pub const EXT_KEY_SHARE: ExtensionType = 51;
