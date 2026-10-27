
mod common;
mod handshake;
mod record;

#[derive(Debug)]
pub struct Conn {
    // Connection details would go here
}

pub fn dial(host_and_port: &str) -> Option<Conn> {
    println!("Dialing {}...", host_and_port);
    Some(Conn {})
}

impl Conn {
    pub fn write(&mut self, data: &str) -> Result<(), &'static str> {
        println!("Writing data: {}", data);
        Ok(())
    }

    pub fn read(&mut self) -> Result<String, &'static str> {
        println!("Reading data...");
        Ok("HTTP/1.1 200 OK\r\n\r\n".to_string())
    }
}
