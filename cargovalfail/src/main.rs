use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Greeting {
    message: String,
}

fn main() {
    let g = Greeting {
        message: "hello from cargovalfail".to_string(),
    };
    println!("{}", serde_json::to_string(&g).unwrap());
}
