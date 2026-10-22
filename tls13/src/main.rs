
mod tls13;

fn main() {
    println!("Hello, world!");
    let mut conn = tls13::dial("example.com:443").unwrap();
    // Do something with the connection
    println!("Connection established: {:?}", conn);
    conn.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
    conn.read().unwrap();
}
