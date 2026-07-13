
use serde::Serialize;
use serde::Deserialize;

#[derive(Serialize)]
struct AddRequest {
    token: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct UploadRequest {
    filename: String,
    content: String,
}

#[derive(Deserialize)]
pub struct SearchResult {
    pub files: Vec<String>,
}

#[derive(Deserialize)]
pub struct StatResult {
    pub size: u64,
    pub is_dir: bool,

    pub mode: u32,

    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,

    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    
    pub blocks: u64,
    pub blksize: u32,
    pub rdev: u32,
}

#[derive(Serialize)]
struct DeleteRequest {
    parent_token: String,
    ciphertext: String,
    path_token: String,
}

use crate::crypto;

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

pub fn upload(
    filename: &str,
    content: &str,
) -> Result<(), Box<dyn std::error::Error>> {

    let req = UploadRequest {
        filename: filename.to_string(),
        content: content.to_string(),
    };

    let client = reqwest::blocking::Client::new();

    println!(
        "upload filename={} content={:?}",
        filename,
        content,
    );

    let response = client
        .post("http://192.168.11.8:2226/upload")
        .json(&req)
        .send()?;

    if !response.status().is_success() {
        return Err(
            format!(
                "upload failed: {}",
                response.status()
            )
            .into(),
        );
    }

    Ok(())
}

pub fn download(
    token: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>>
{
    let url =
        format!(
            "http://192.168.11.8:2226/download?token={}",
            token
        );

    let response =
        reqwest::blocking::get(url)?;

    if !response.status().is_success() {
        return Err(
            format!(
                "download failed: {}",
                response.status()
            )
            .into()
        );
    }

    let encoded = response.text()?;
    let plaintext = crypto::decrypt(&encoded);

    Ok(
        plaintext.into_bytes()
    )
}

pub fn delete(
    parent_token: &str,
    ciphertext: &str,
    path_token: &str,
) -> Result<(), Box<dyn std::error::Error>>
{
    let req = DeleteRequest {
        parent_token: parent_token.to_string(),
        ciphertext: ciphertext.to_string(),
        path_token: path_token.to_string(),
    };

    let client = reqwest::blocking::Client::new();

    let response = client
        .post("http://192.168.11.8:2226/delete")
        .json(&req)
        .send()?;

    if !response.status().is_success() {
        return Err(
            format!(
                "delete failed: {}",
                response.status()
            )
            .into(),
        );
    }

    Ok(())
}