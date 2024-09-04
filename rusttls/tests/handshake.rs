use std::{
    io::{Read, Write},
    net::TcpStream,
};

use ring::{
    aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_128_GCM, NONCE_LEN}, agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519}, digest::{digest, SHA256, SHA256_OUTPUT_LEN}, hkdf::{self, KeyType, Prk, Salt, HKDF_SHA256}, rand::SystemRandom
};
use rusttls::{
    handshake::{
        CipherSuite, Extension, ExtensionType, SignatureAlgorithm, SupportedGroup, TlsHandshake,
    },
    record::{self, TlsContentType, TlsProtocolVersion, TlsRecord},
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
    let rng = SystemRandom::new();
    let client_private_key = EphemeralPrivateKey::generate(&X25519, &rng)
        .expect("Failed to generate client private key");
    let client_public_key = client_private_key
        .compute_public_key()
        .expect("Failed to compute client public key")
        .as_ref()
        .to_vec();
    let extensions = vec![
        Extension::server_name("localhost".into()),
        Extension::supported_groups(vec![SupportedGroup::X25519, SupportedGroup::SECP256R1]),
        Extension::signature_algorithms(vec![
            SignatureAlgorithm::EcdsaSecp256r1Sha256,
            SignatureAlgorithm::Ed25519,
        ]),
        Extension::ec_point_formats(),
        Extension::supported_versions(),
        Extension::key_share_client(SupportedGroup::X25519, client_public_key),
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
        data.clone(),
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
        assert_eq!(CipherSuite::TLS_AES_128_GCM_SHA256, cipher_suite);
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
        let key_share = server_extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::KeyShare)
            .unwrap()
            .clone()
            .key_share_server_value();
        assert_eq!(SupportedGroup::X25519, key_share.0);

        let server_public_key = UnparsedPublicKey::new(&X25519, key_share.1);
        let mut handshake_messages = data;
        let server_hello_bytes = res[5..(5 + len)].to_vec();
        handshake_messages.extend_from_slice(&server_hello_bytes);
        let digest = digest(&SHA256, &handshake_messages);
        println!("sha256 hash: {:?}", digest);
        let shared_key = agree_ephemeral(client_private_key, &server_public_key, |material| {
            material.to_vec()
        })
        .expect("Failed to calculate shared key");

        // Key Schedule
        let salt = [0u8];
        let pre_shared_key = [0u8];

        // HKDF=Extract(salt, input)
        let early_secret = Salt::new(HKDF_SHA256, &salt).extract(&pre_shared_key);
        let first_block_result = derive_secret(early_secret, "derived".as_bytes(), "".as_bytes());

        // 2nd key schedule block
        let handshake_secret = Salt::new(HKDF_SHA256, &shared_key).extract(&first_block_result);
        let client_handshake_traffic_secret = derive_secret(handshake_secret.clone(), "c hs traffic".as_bytes(), &handshake_messages);
        println!("c hs traffic {:?}", client_handshake_traffic_secret);
        let server_handshake_traffic_secret = derive_secret(handshake_secret, "s hs traffic".as_bytes(), &handshake_messages);
        println!("s hs traffic {:?}", server_handshake_traffic_secret);

        let start = 5 + len;
        if (record::TlsContentType::ChangeCipherSpec as u8) == res[start] {
            println!("Skip ChangeCipherSpec");
            assert_eq!(3, res[start + 1]);
            assert_eq!(3, res[start + 2]);
            // length
            assert_eq!(0, res[start + 3]);
            assert_eq!(1, res[start + 4]);
            // payload
            assert_eq!(1, res[start + 5]);
        } else {
            panic!("Fail");
        }

        // https://web3developer.io/authenticated-encryption-in-rust-using-ring/
        struct CounterNonceSequence(u32);
        impl NonceSequence for CounterNonceSequence {
            fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
                let mut nonce_bytes = vec![0; NONCE_LEN];
                let bytes = self.0.to_be_bytes();
                nonce_bytes[8..].copy_from_slice(&bytes);
                self.0 += 1;

                Nonce::try_assume_unique_for_key(&nonce_bytes)
            }
        }
        let nonce_sequence = CounterNonceSequence(1);

        let start = start + 6;
        println!("{:?}", res[start..start+10].bytes());
        if (record::TlsContentType::ApplicationData as u8) == res[start] {
            assert_eq!(3, res[start + 1]);
            assert_eq!(3, res[start + 2]);
            let len = ((res[start + 3] as usize) << 8) + (res[start + 4] as usize);
            println!("encrypted data: {:?}", res[start..(start + 5 + len)].bytes());
            let encrypted_data = &res[(start+5)..(start+5+len)];
            println!("{:?}", encrypted_data.bytes());
            println!("TODO: Decrypt App Data");

            let len = convert(len as u16);
            let associated_data = [
                TlsContentType::ApplicationData as u8,
                // protocol version
                res[start + 1], res[start + 2],
                len[0], len[1],
            ];
            let associated_data = Aad::from(associated_data);

            assert_eq!(AES_128_GCM.key_len(), server_handshake_traffic_secret.len());
            let unbound_key = UnboundKey::new(&AES_128_GCM, &server_handshake_traffic_secret).unwrap();
            let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);
        } else {
            panic!("Fail");
        }
    } else {
        panic!("not a server hello");
    }
}

/// RFC 8446 TLS1.3: 7.1 Key Schedule
fn derive_secret(secret: Prk, label: &[u8], messages: &[u8]) -> Vec<u8> {
    // TODO: use hash designated by the cipher suite.
    let hash = digest(&SHA256, messages);
    // TODO: construct hkdf label = length + "tls13 " + label + hash
    let hkdf_label  = &[&convert(hash.clone().as_ref().len() as u16), "tls13 ".as_bytes(), label, hash.as_ref()];
    let key_material = secret.expand(hkdf_label, HKDF_SHA256).expect("HKDF Expand failed");
    let mut derived_secret = vec![0; SHA256_OUTPUT_LEN];
    key_material.fill(&mut derived_secret).expect("Key material fill failed");
    derived_secret
}

fn convert(num: u16) -> [u8; 2] {
    let lower = (num & 0xff) as u8;
    let upper = (num >> 8) as u8;
    [upper, lower]
}
