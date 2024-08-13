use std::{
    io::{Read, Write},
    net::TcpStream,
};

use rusttls::{
    handshake::{
        CipherSuite, Extension, ExtensionType, SignatureAlgorithm, SupportedGroup, TlsHandshake,
    },
    record::{self, TlsProtocolVersion, TlsRecord},
};

#[test]
fn ngx_client_hello() {
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
    // taken from: https://github.com/briansmith/ring/blob/main/src/ec/curve25519/x25519.rs#L217C26-L222C15
    let public_key = vec![
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    let private_key = vec![
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    let extensions = vec![
        Extension::server_name("localhost".into()),
        Extension::supported_groups(vec![SupportedGroup::X25519, SupportedGroup::SECP256R1]),
        Extension::signature_algorithms(vec![
            SignatureAlgorithm::EcdsaSecp256r1Sha256,
            SignatureAlgorithm::Ed25519,
        ]),
        Extension::ec_point_formats(),
        Extension::supported_versions(),
        Extension::key_share_client(SupportedGroup::X25519, public_key.clone()),
    ];

    let mut client_hello = TlsHandshake::ClientHello(
        protocol_version,
        random,
        legacy_session_id,
        cipher_suites.clone(),
        extensions,
    );
    let data = client_hello.as_bytes();
    let mut record = TlsRecord::new(
        record::TlsContentType::Handshake,
        TlsProtocolVersion::tls1_0(),
        data,
    );
    let bytes = record.as_bytes();
    println!("write: {:?}", bytes);
    stream
        .write(bytes.as_ref())
        .expect("Failed to write record");
    let mut res = [0; 16384];
    stream.read(&mut res).expect("Failed to read response");
    println!("read: {:?}", res);

    assert_eq!(record::TlsContentType::Handshake as u8, res[0]);
    assert_eq!(3, res[1]);
    assert_eq!(3, res[2]);
    // ServerHello
    assert_eq!(2, res[5]);
    let len = ((res[3] as usize) << 8) + (res[4] as usize);
    if let TlsHandshake::ServerHello(
        version,
        _server_random,
        server_session_id,
        cipher_suite,
        server_extensions,
    ) = TlsHandshake::from_bytes(res[5..(5 + len)].to_vec())
    {
        assert_eq!(TlsProtocolVersion::tls1_2(), version);
        assert_eq!(legacy_session_id, server_session_id);
        assert!(cipher_suites.contains(&cipher_suite));
        assert_eq!(
            TlsProtocolVersion::tls1_3(),
            *Extension::supported_versions_value(
                server_extensions
                    .iter()
                    .find(|e| e.extension_type == ExtensionType::SupportedVersions)
                    .unwrap()
                    .clone()
            )
            .first()
            .unwrap()
        );
        let key_share = Extension::key_share_server_value(
            server_extensions.iter().find(|e| e.extension_type == ExtensionType::KeyShare)
            .unwrap().clone()
        );
        assert_eq!(SupportedGroup::X25519, key_share.0);
    } else {
        panic!("not a server hello");
    }
}
