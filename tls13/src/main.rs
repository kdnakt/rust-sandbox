mod tls13;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use aws_lc_rs::agreement::*;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

fn main() {
    println!("Hello, world!");
    let rng = SystemRandom::new();
    let private_key = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    // create a public key from the private key, as Vec<u8>
    let public_key = private_key.compute_public_key().unwrap().as_ref().to_vec();
    let mut random = [0u8; 32];
    rng.fill(&mut random).unwrap();

    let client_hello = tls13::client_hello::new_client_hello(random, vec![
        tls13::extensions::server_name_extension("example.com"),
        tls13::extensions::supported_versions_extension(),
        tls13::extensions::signature_algorithms_extension(),
        tls13::extensions::supported_groups_extension(),
        tls13::extensions::key_share_extension(public_key),
    ]);
    println!("Client Hello: {:?}", client_hello);

    let h = tls13::handshake::Handshake::new(tls13::common::HSTYPE_CLIENT_HELLO, client_hello.marshall());
    println!("Handshake: {:?}", h);

    let rec = tls13::record::TlsPlaintext::new(tls13::common::CONTENT_TYPE_HANDSHAKE, h.marshall());
    println!("Record: {:?}", rec);

    // tcp connection to example.com:443
    let mut conn = TcpStream::connect("example.com:443").unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    conn.write(&rec.marshall()).unwrap();
    for i in 0..5 {
        let response = tls13::record::read_record(&mut conn);
        if response.is_err() {
            println!("Failed to read record: {:?}", response.err());
            break;
        }
        println!("Response {}: {:?}", i, response.unwrap());
    }
}
