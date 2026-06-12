use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem,
    MountOption, ReplyAttr, ReplyDirectory,
    Request, ReplyEntry, ReplyCreate
};

use serde::Serialize;
use serde::Deserialize;

use std::ffi::OsStr;

use std::collections::HashMap;

use sha2::{
    Digest,
    Sha256,
};

use aes_gcm::{
    Aes256Gcm,
    KeyInit,
    Nonce,
    aead::Aead,
};

use rand::RngCore;
use base64::{
    engine::general_purpose::STANDARD,
    Engine,
};

const TTL: Duration = Duration::from_secs(1);

const ROOT_INO: u64 = 1;

const KEY: [u8; 32] = *b"01234567890123456789012345678901";

#[derive(Serialize)]
struct AddRequest {
    token: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct SearchResult {
    files: Vec<String>,
}

struct MyFS {
    next_inode: u64,
    inode_to_query: HashMap<u64, String>,
    query_to_inode: HashMap<String, u64>,
}

impl MyFS {
    fn get_inode(&mut self, query: &str) -> u64 {
        if let Some(&ino) = self.query_to_inode.get(query) {
            return ino;
        }

        let ino = self.next_inode;
        self.next_inode += 1;

        self.query_to_inode.insert(query.to_string(), ino);
        self.inode_to_query.insert(ino, query.to_string());

        return ino;
    }

    fn make_token(
        secret: &str,
        query: &str,
    ) -> String {

        let mut hasher =
            Sha256::new();

        hasher.update(secret);
        hasher.update(query);

        hex::encode(
            hasher.finalize()
        )
    }


    fn encrypt_filename(
        key: &[u8; 32],
        filename: &str,
    ) -> String {

        let cipher =
            Aes256Gcm::new_from_slice(key)
                .unwrap();

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng()
            .fill_bytes(&mut nonce_bytes);

        let nonce =
            Nonce::from_slice(&nonce_bytes);

        let ciphertext =
            cipher.encrypt(
                nonce,
                filename.as_bytes(),
            )
            .unwrap();

        let mut result =
            nonce_bytes.to_vec();

        result.extend(ciphertext);

        STANDARD.encode(result)
    }

    fn decrypt_filename(
        key: &[u8; 32],
        encoded: &str,
    ) -> String {

        let data =
            STANDARD.decode(encoded)
                .unwrap();

        let (nonce_bytes, ciphertext) =
            data.split_at(12);

        let cipher =
            Aes256Gcm::new_from_slice(key)
                .unwrap();

        let nonce =
            Nonce::from_slice(nonce_bytes);

        let plaintext =
            cipher.decrypt(
                nonce,
                ciphertext,
            )
            .unwrap();

        String::from_utf8(plaintext)
            .unwrap()
    }

    fn add_index(
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
}

impl Filesystem for MyFS {

    fn lookup(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        reply: ReplyEntry,
    ) {
        println!(
            "lookup(parent={}, name={:?})",
            parent,
            name
        );

        let parent_query = match self.inode_to_query.get(&parent) {
            Some(q) => q.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        //
        // 親ディレクトリを検索
        //
        let token =
            if parent_query.is_empty() {
                ".".to_string()
            } else {
                parent_query.clone()
            };

        let url = format!(
            "http://192.168.11.8:2226/search?token={}",
            MyFS::make_token("oreore-key", &token),
        );

        let result: SearchResult =
            match reqwest::blocking::get(&url) {
                Ok(res) => match res.json() {
                    Ok(json) => json,
                    Err(_) => {
                        reply.error(libc::EIO);
                        return;
                    }
                },
                Err(_) => {
                    reply.error(libc::EIO);
                    return;
                }
            };

        //
        // lookup対象名
        //
        let target_name =
            name.to_string_lossy().to_string();

        //
        // 復号して存在確認
        //
        let mut found = false;

        for encrypted_name in &result.files {

            let plain_name =
                MyFS::decrypt_filename(&KEY ,encrypted_name);

            if plain_name == target_name {
                found = true;
                break;
            }
        }

        if !found {
            println!("not found");
            reply.error(libc::ENOENT);
            return;
        }

        let query =
            if parent_query.is_empty() {
                name.to_string_lossy().to_string()
            } else {
                format!(
                    "{}/{}",
                    parent_query,
                    name.to_string_lossy()
                )
            };

        let ino = self.get_inode(&query);
        let kind = if query.ends_with(".txt") {
                FileType::RegularFile
            } else {
                FileType::Directory
            };

        let attr = FileAttr {
            ino: ino,
            size: 0,
            blocks: 0,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: kind,
            perm: 0o644,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 512,
            flags: 0,
        };

        reply.entry(&TTL, &attr, 0);
        return;
    }

    fn getattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        reply: ReplyAttr,
    ) {
        println!("getattr({})", ino);

        let query = match self.inode_to_query.get(&ino) {
            Some(q) => q.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let kind = if query.is_empty() {
            FileType::Directory
        } else {
            let kind2 = if query.contains(".") {
                FileType::RegularFile
            } else {
                FileType::Directory
            };
            kind2
        };

        let attr = FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind,
            perm: 0o644,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 512,
            flags: 0,
        };

        reply.attr(&TTL, &attr);
        return;
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _offset: i64,
        mut reply: ReplyDirectory,
    ) {
        println!("readdir({}, {})", ino, _offset);

        if _offset != 0 {
            reply.ok();
            return;
        }

        // inode → query
        let mut query = match self.inode_to_query.get(&ino) {
            Some(q) => q.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // ルートは子ディレクトリを出す
        if query.is_empty() {
            query = ".".to_string();
        }

        println!("query = {}", query);

        // どのinodeでも同じ処理
        let token = MyFS::make_token("oreore-key", &query);

        let url = format!(
            "http://192.168.11.8:2226/search?token={}",
            token
        );

        let result: SearchResult = match reqwest::blocking::get(&url) {
            Ok(res) => match res.json() {
                Ok(json) => json,
                Err(_) => {
                    reply.error(libc::EIO);
                    return;
                }
            },
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        for enc_name in result.files {
            let file =
                MyFS::decrypt_filename(
                    &KEY,
                    &enc_name,
                );

            let child_query = format!("{}/{}", query, file);
            let child_ino = self.get_inode(&child_query);

            let _ = reply.add(
                child_ino,
                1,
                FileType::RegularFile,
                file,
            );
        }

        reply.ok();
        return;
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        println!(
            "create(parent={}, name={:?}, mode={}, flags={})",
            parent,
            name,
            mode,
            flags,
        );

        let parent_query =
            match self.inode_to_query.get(&parent) {
                Some(q) => q.clone(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

        let query =
            if parent_query.is_empty() {
                name.to_string_lossy().to_string()
            } else {
                format!(
                    "{}/{}",
                    parent_query,
                    name.to_string_lossy()
                )
            };

        println!("parent={}, query={}", parent_query, query);

        let ino = self.get_inode(&query);

        let attr = FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 512,
            flags: 0,
        };

        let mut token =
            if parent_query.is_empty() {
                ".".to_string()
            } else {
                parent_query.clone()
            };

        token = MyFS::make_token("oreore-key", &token);
        let ciphertext = MyFS::encrypt_filename(&KEY, &query);

        match MyFS::add_index(
            &token,
            &ciphertext,
        ) {
            Ok(_) => {
                println!("index updated");
            }
            Err(e) => {
                println!("index update failed: {}", e);
            }
        }

        reply.created(
            &TTL,
            &attr,
            0,
            0,
            flags as u32,
        );
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<u64>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        println!("setattr({})", ino);

        let attr = FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 512,
            flags: 0,
        };
        reply.attr(&TTL, &attr);
    }
}
/*
fn main() {

    let key =
        *b"01234567890123456789012345678901";

    let encrypted =
        MyFS::encrypt_filename(
            &key,
            "art",
        );

    println!(
        "encrypted = {}",
        encrypted
    );

    let decrypted =
        MyFS::decrypt_filename(
            &key,
            &encrypted,
        );

    println!(
        "decrypted = {}",
        decrypted
    );
}*/

fn main() {

    let mountpoint = std::env::args()
        .nth(1)
        .expect("mountpoint");

    fuser::mount2(
        MyFS {
            inode_to_query: HashMap::from([
                (ROOT_INO, "".to_string()),
            ]),
            query_to_inode: HashMap::from([
                ("".to_string(), ROOT_INO),
            ]),
            next_inode: 2,
        },
        mountpoint,
        &[MountOption::FSName("ssefs".into())],
    )
    .unwrap();
}