
mod tls13;

fn main() {
    println!("Hello, world!");
    tls13::dial("example.com:443");
}
