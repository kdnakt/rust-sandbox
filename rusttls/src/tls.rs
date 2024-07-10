

pub struct TlsRecord {
    pub protocol_version: TlsProtocolVersion,
    pub content_type: TlsContentType,
}

pub enum TlsProtocolVersion {
    TLS13,
}

pub enum TlsContentType {
    Handshake,
    ApplicationData,
    ChangeCipherSpec,
    Alert,
}
