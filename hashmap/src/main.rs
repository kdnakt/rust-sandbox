use std::{
    any::Any,
    collections::HashMap,
};

trait Object {
    fn as_any(&self) -> &dyn Any;
    fn name(&self) -> String;
}

#[derive(Debug)]
struct Identifier {
    myname: String
}

impl Object for Identifier {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn name(&self) -> String {
        self.myname.to_string()
    }
}

fn main() {
    let mut map: HashMap<String, Box<dyn Object>> = HashMap::new();

    let value = Box::new(Identifier {
        myname: "VALUE".to_string(),
    });
    map.insert("key".to_string(), value);

    match map.get("key") {
        Some(object) => {
            let identifier = object.as_any()
                    .downcast_ref::<Identifier>()
                    .expect("Not an Identifier");
            println!("some: {:?}", identifier);
        },
        _ => println!("_"),
    }
}
