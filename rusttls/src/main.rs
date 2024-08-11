use std::io::prelude::*;
use std::net::TcpStream;

use handshake::{CipherSuite, Extension, SupportedGroup};
use record::{TlsProtocolVersion, TlsRecord};

mod handshake;
pub mod record;

fn main() -> std::io::Result<()> {
    println!("Hello, world!");

    let mut stream = TcpStream::connect("127.0.0.1:8443")?;

    let protocol_version = record::TlsProtocolVersion::tls1_2();
    let random: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let legacy_session_id: [u8; 32] = [
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
        34, 35, 36, 37, 38, 39, 40, 41, 42,
    ];
    let cipher_suites = vec![
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
    ];
    let extensions = vec![
        Extension::server_name("localhost".into()),
        Extension::supported_groups(vec![SupportedGroup::X25519, SupportedGroup::SECP256R1]),
    ];

    let mut client_hello = handshake::TlsHandshake::ClientHello(
        protocol_version,
        random,
        legacy_session_id,
        cipher_suites,
        extensions,
    );
    let mut record = TlsRecord {
        content_type: record::TlsContentType::Handshake,
        length: 0,
        protocol_version: TlsProtocolVersion::tls1_2(),
        data: client_hello.as_bytes(),
    };
    println!("{:?}", record.as_bytes());
    stream.write(record.as_bytes().as_ref())?;
    let mut res = [9; 16384];
    stream.read(&mut res)?;
    println!("response: {:?}", res);
    Ok(())
}
