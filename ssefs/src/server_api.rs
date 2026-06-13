
use serde::Serialize;
use serde::Deserialize;

#[derive(Serialize)]
struct AddRequest {
    token: String,
    ciphertext: String,
}

#[derive(Deserialize)]
pub struct SearchResult {
    pub files: Vec<String>,
}

pub fn add_index(
    token: &str,
    ciphertext: &str,
) -> Result<(), Box<dyn std::error::Error>>
{
    let req = AddRequest {
        token: token.to_string(),
        ciphertext: ciphertext.to_string(),
    };

    let client = reqwest::blocking::Client::new();

    client
        .post("http://192.168.11.8:2226/add")
        .json(&req)
        .send()?;

    Ok(())
}