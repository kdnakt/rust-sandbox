use serde::Deserialize;
use serde_json::Result;

#[derive(Deserialize, Debug)]
struct Person {
    name: String,
    age: u8,
    phones: Vec<String>,
}

fn main() -> Result<()> {
    println!("Hello, world!");

    let data = include_bytes!("./person.json");
    let p: Person = serde_json::from_slice(data)?;
    println!("Please call {} at the number {}", p.name, p.phones[0]);

    Ok(())
}
