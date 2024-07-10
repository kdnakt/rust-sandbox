use std::io::prelude::*;
use std::net::TcpStream;

mod tls;

fn main() -> std::io::Result<()> {
    println!("Hello, world!");

    let mut stream = TcpStream::connect("127.0.0.1:8443")?;
    stream.write(&[7])?;
    stream.read(&mut [0; 128])?;
    Ok(())
}
