
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
    gid: u32,
}

#[derive(Serialize)]
struct MkdirRequest {
    filename: String,
    gid: u32,
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

#[derive(Serialize)]
struct SetattrRequest {
    token: String,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    atime: Option<i64>,
    mtime: Option<i64>,
    ctime: Option<i64>,
    size: Option<u64>,
}

#[derive(Serialize)]
struct RemoveIndexRequest {
    parent_token: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct RenameRequest {
    old_path_token: String,
    new_path_token: String,
    is_dir: bool,
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

pub fn setattr(
    token: &str,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    atime: Option<i64>,
    mtime: Option<i64>,
    ctime: Option<i64>,
    size: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = SetattrRequest {
        token: token.to_string(),
        mode,
        uid,
        gid,
        atime,
        mtime,
        ctime,
        size,
    };

    let client = reqwest::blocking::Client::new();

    let response = client
        .post("http://192.168.11.8:2226/setattr")
        .json(&req)
        .send()?;

    if !response.status().is_success() {
        return Err(
            format!(
                "setattr failed: {}",
                response.status()
            )
            .into(),
        );
    }

    Ok(())
}

pub fn upload(
    filename: &str,
    content: &str,
    gid: u32,
) -> Result<(), Box<dyn std::error::Error>> {

    let req = UploadRequest {
        filename: filename.to_string(),
        content: content.to_string(),
        gid,
    };

    let client = reqwest::blocking::Client::new();

    println!(
        "upload filename={} content={:?} gid={}",
        filename,
        content,
        gid,
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

pub fn mkdir(
    filename: &str,
    gid: u32,
) -> Result<(), Box<dyn std::error::Error>> {

    let req = MkdirRequest {
        filename: filename.to_string(),
        gid,
    };

    let client = reqwest::blocking::Client::new();

    println!(
        "upload foldername={} gid={}",
        filename,
        gid,
    );

    let response = client
        .post("http://192.168.11.8:2226/mkdir")
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

pub fn remove_index(
    parent_token: &str,
    ciphertext: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = RemoveIndexRequest {
        parent_token: parent_token.to_string(),
        ciphertext: ciphertext.to_string(),
    };

    let client = reqwest::blocking::Client::new();

    let response = client
        .post("http://192.168.11.8:2226/remove_index")
        .json(&req)
        .send()?;

    if !response.status().is_success() {
        return Err(
            format!(
                "remove_index failed: {}",
                response.status()
            )
            .into(),
        );
    }

    Ok(())
}

pub fn rename(
    old_path_token: &str,
    new_path_token: &str,
    is_dir: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = RenameRequest {
        old_path_token: old_path_token.to_string(),
        new_path_token: new_path_token.to_string(),
        is_dir,
    };

    let client = reqwest::blocking::Client::new();

    let response = client
        .post("http://192.168.11.8:2226/rename")
        .json(&req)
        .send()?;

    if !response.status().is_success() {
        return Err(
            format!(
                "rename failed: {}",
                response.status()
            )
            .into(),
        );
    }

    Ok(())
}
