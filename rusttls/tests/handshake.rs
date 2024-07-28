use std::{
    io::{Read, Write},
    net::TcpStream,
};

use rusttls::{
    handshake::{CipherSuite, Extension, SupportedGroup, TlsHandshake},
    record::{self, TlsProtocolVersion, TlsRecord},
};

#[test]
fn client_hello() {
    let mut stream = TcpStream::connect("127.0.0.1:8443").expect("Failed to connect to server");

    let protocol_version = TlsProtocolVersion::tls1_2();
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
        Extension::supported_versions(),
    ];

    let mut client_hello = TlsHandshake::ClientHello(
        protocol_version,
        random,
        legacy_session_id,
        cipher_suites,
        extensions,
    );
    let data = client_hello.as_bytes();
    let mut record = TlsRecord::new(
        record::TlsContentType::Handshake,
        TlsProtocolVersion::tls1_2(),
        data,
    );
    // println!("{:?}", record.as_bytes());
    stream
        .write(record.as_bytes().as_ref())
        .expect("Failed to write record");
    let mut res = [0; 128];
    stream.read(&mut res).expect("Failed to read response");
    println!("res: {:?}", res);

    assert_eq!(record::TlsContentType::Handshake as u8, res[0]);
    assert_eq!(3, res[1]);
    assert_eq!(3, res[2]);
}
