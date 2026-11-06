mod tls13;

use aws_lc_rs::agreement::*;
use aws_lc_rs::encoding::AsBigEndian;
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
}
