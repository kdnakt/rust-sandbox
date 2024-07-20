use std::io::prelude::*;
use std::net::TcpStream;

use record::TlsRecord;

mod record;
mod handshake;

fn main() -> std::io::Result<()> {
    println!("Hello, world!");

    let mut stream = TcpStream::connect("127.0.0.1:8443")?;

    let mut record = TlsRecord {
        content_type: record::TlsContentType::Handshake,
        // TLS 1.2
        protocol_version: record::TlsProtocolVersion { major: 3, minor: 3 },
        length: 0,
        data: vec![],
    };
    println!("{:?}", record.as_bytes());
    stream.write(record.as_bytes().as_ref())?;
    stream.read(&mut [0; 128])?;
    Ok(())
}
