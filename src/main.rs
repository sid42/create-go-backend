use serde::Serialize;

use tinytemplate::TinyTemplate;
use std::error::Error;

#[derive(Serialize)]
struct Context { 
    name: String,
}

static TEMPLATE : &'static str = "Hello {name}!";

pub fn main() {
    let mut tt = TinyTemplate::new();
    tt.add_template("hello", TEMPLATE);

    let context = Context {
        name: "World".to_string(),
    };

    let rendered = tt.render("hello", &context);
    println!("{}", rendered.unwrap());
}
