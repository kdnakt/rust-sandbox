
use crate::tls13::common::*;

struct TlsPlaintext {
    content_type: ContentType,
    version: TlsVersion,
    length: u16,
    payload: Vec<u8>,
}
