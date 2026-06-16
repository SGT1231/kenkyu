
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem,
    ReplyAttr, ReplyDirectory,
    Request, ReplyEntry, ReplyCreate
};

use std::ffi::OsStr;
use std::collections::HashMap;

use crate::crypto;
use crate::server_api;

const TTL: Duration = Duration::from_secs(1);
const KEY: [u8; 32] = *b"01234567890123456789012345678901";

pub struct MyFS {
    pub next_inode: u64,
    pub inode_to_query: HashMap<u64, String>,
    pub query_to_inode: HashMap<String, u64>,
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
            crypto::make_token("oreore-key", &token),
        );

        let result: server_api::SearchResult =
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
                crypto::decrypt_filename(&KEY ,encrypted_name);

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
        let token =
            if query.is_empty() {
                crypto::make_token("oreore-key", ".")
            } else {
                crypto::make_token("oreore-key", &query)
            };

        let url = format!(
            "http://192.168.11.8:2226/stat?token={}",
            token,
        );

        let result: server_api::StatResult =
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

        let kind =
            if result.is_dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            };

        let attr = FileAttr {
            ino,
            size: result.size,
            blocks: (result.size + 511) / 512,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind,
            perm: 0o644,
            nlink: 1,
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

    let token =
        if query.is_empty() {
            crypto::make_token("oreore-key", ".")
        } else {
            crypto::make_token("oreore-key", &query)
        };

    let url = format!(
        "http://192.168.11.8:2226/stat?token={}",
        token,
    );

    let result: server_api::StatResult =
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

    let kind =
        if result.is_dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        };

    println!("size={}", result.size);
    let attr = FileAttr {
        ino,
        size: result.size,
        blocks: (result.size + 511) / 512,
        atime: SystemTime::now(),
        mtime: SystemTime::now(),
        ctime: SystemTime::now(),
        crtime: SystemTime::now(),
        kind,
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

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if _offset != 0 {
            reply.ok();
            return;
        }
        
        println!("readdir({}, {})", ino, _offset);

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
        let token = crypto::make_token("oreore-key", &query);

        let url = format!(
            "http://192.168.11.8:2226/search?token={}",
            token
        );

        let result: server_api::SearchResult = match reqwest::blocking::get(&url) {
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
                crypto::decrypt_filename(
                    &KEY,
                    &enc_name,
                );

            let child_query = format!("{}/{}", query, file);
            let child_ino = self.get_inode(&child_query);

            let _ = reply.add(
                child_ino,
                1,
                FileType::Directory,
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

        token = crypto::make_token("oreore-key", &token);
        let ciphertext = crypto::encrypt_filename(&KEY, &query);

        match server_api::add_index(
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

        let upload_file_token = crypto::make_token("oreore-key", &query);
        match server_api::upload(
            &upload_file_token,
            "",
        ) {
            Ok(_) => {
                println!("upload ok");
            }
            Err(e) => {
                println!("upload failed: {}", e);
                reply.error(libc::EIO);
                return;
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