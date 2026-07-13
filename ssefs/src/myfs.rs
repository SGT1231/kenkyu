
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem,
    ReplyAttr, ReplyDirectory, ReplyData,
    Request, ReplyEntry, ReplyCreate, ReplyWrite,
    ReplyEmpty
};

use std::ffi::OsStr;
use std::collections::HashMap;

use crate::crypto;
use crate::server_api;

const TTL: Duration = Duration::from_secs(60);

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

        let parent_path = match self.inode_to_query.get(&parent) {
            Some(q) => q.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        //
        // 親ディレクトリを検索
        //
        let parent_token =
            if parent_path.is_empty() {
                ".".to_string()
            } else {
                parent_path.clone()
            };

        let url = format!(
            "http://192.168.11.8:2226/search?token={}",
            crypto::make_token("oreore-key", &parent_token),
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
        let target_name = name.to_string_lossy().to_string();

        //
        // 復号して存在確認
        //
        let mut found = false;

        for encrypted_name in &result.files {

            let plain_name = crypto::decrypt(encrypted_name);

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

        let path =
            if parent_path.is_empty() {
                name.to_string_lossy().to_string()
            } else {
                format!(
                    "{}/{}",
                    parent_path,
                    name.to_string_lossy()
                )
            };

        let ino = self.get_inode(&path);
        let path_token =
            if path.is_empty() {
                crypto::make_token("oreore-key", ".")
            } else {
                crypto::make_token("oreore-key", &path)
            };

        let url = format!(
            "http://192.168.11.8:2226/stat?token={}",
            path_token,
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
            blocks: result.blocks,

            atime: UNIX_EPOCH + Duration::from_secs(result.atime as u64),
            mtime: UNIX_EPOCH + Duration::from_secs(result.mtime as u64),
            ctime: UNIX_EPOCH + Duration::from_secs(result.ctime as u64),
            crtime: UNIX_EPOCH + Duration::from_secs(result.ctime as u64),

            kind,
            perm: result.mode as u16,

            nlink: result.nlink,
            uid: result.uid,
            gid: result.gid,

            rdev: result.rdev,
            blksize: result.blksize,
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

        let path = match self.inode_to_query.get(&ino) {
            Some(q) => q.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let path_token =
            if path.is_empty() {
                crypto::make_token("oreore-key", ".")
            } else {
                crypto::make_token("oreore-key", &path)
            };

        let url = format!(
            "http://192.168.11.8:2226/stat?token={}",
            path_token,
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

            atime: UNIX_EPOCH + Duration::from_secs(result.atime as u64),
            mtime: UNIX_EPOCH + Duration::from_secs(result.mtime as u64),
            ctime: UNIX_EPOCH + Duration::from_secs(result.ctime as u64),
            crtime: UNIX_EPOCH + Duration::from_secs(result.ctime as u64),

            kind,
            perm: result.mode as u16,

            nlink: result.nlink,
            uid: result.uid,
            gid: result.gid,
            
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
        let mut path = match self.inode_to_query.get(&ino) {
            Some(q) => q.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // ルートは子ディレクトリを出す
        if path.is_empty() {
            path = ".".to_string();
        }

        // どのinodeでも同じ処理
        let token = crypto::make_token("oreore-key", &path);
        println!("token = {}", token);

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

        let _ = reply.add(ino, 1, FileType::Directory, ".");
        let parent_path =
            match path.rfind('/') {
                Some(pos) => &path[..pos],
                None => "",
            };

        let parent_ino = self.get_inode(parent_path);
        println!("parent_ino = {}", parent_ino);
        let _ = reply.add(parent_ino, 2, FileType::Directory, "..");

        let mut offset = 3;
        for enc_path in result.files {
            let filename = crypto::decrypt(&enc_path);

            let child_path = format!("{}/{}", path, filename);
            let child_ino = self.get_inode(&child_path);

            let _ = reply.add(
                child_ino,
                offset,
                FileType::Directory,
                filename,
            );
            offset += 1;
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
        _umask: u32,
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

        let parent_path =
            match self.inode_to_query.get(&parent) {
                Some(q) => q.clone(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

        let name = name.to_string_lossy().to_string();

        let path =
            if parent_path.is_empty() {
                name.clone()
            } else {
                format!(
                    "{}/{}",
                    parent_path,
                    name.to_string()
                )
            };

        let ino = self.get_inode(&path);

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

        let mut parent_token =
            if parent_path.is_empty() {
                ".".to_string()
            } else {
                parent_path.clone()
            };

        parent_token = crypto::make_token("oreore-key", &parent_token);
        let token = crypto::encrypt(&name);

        match server_api::add_index(
            &parent_token,
            &token,
        ) {
            Ok(_) => {
                println!("index updated");
            }
            Err(e) => {
                println!("index update failed: {}", e);
            }
        }

        let path_token = crypto::make_token("oreore-key", &path);
        match server_api::upload(
            &path_token,
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

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {

        println!("read({})", ino);

        let path =
            match self.inode_to_query.get(&ino) {
                Some(q) => q.clone(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

        let path_token = crypto::make_token("oreore-key", &path);

        let data =
            match server_api::download(
                &path_token,
            ) {
                Ok(v) => v,
                Err(_) => {
                    reply.error(libc::EIO);
                    return;
                }
            };

        let start =
            offset as usize;

        let end =
            std::cmp::min(
                start + size as usize,
                data.len(),
            );

        if start >= data.len() {
            reply.data(&[]);
            return;
        }

        reply.data(
            &data[start..end]
        );
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {

        println!("write({})", ino);

        let path =
            match self.inode_to_query.get(&ino) {
                Some(q) => q.clone(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

        let path_token = crypto::make_token("oreore-key", &path);

        let mut content =
            match server_api::download(&path_token) {
                Ok(v) => v,
                Err(_) => {
                    reply.error(libc::EIO);
                    return;
                }
            };

        let start = offset as usize;

        if content.len() < start {
            content.resize(start, 0);
        }

        let end = start + data.len();

        if content.len() < end {
            content.resize(end, 0);
        }

        content[start..end].copy_from_slice(data);

        let encrypted = crypto::encrypt_bytes(&content);

        match server_api::upload(
                &path_token,
                &encrypted,
            ) {
                Ok(_) => {}
                Err(_) => {
                    reply.error(libc::EIO);
                    return;
                }
            }

        reply.written(data.len() as u32);
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        println!(
            "mkdir(parent={}, name={:?})",
            parent,
            name,
        );

        let parent_path =
            match self.inode_to_query.get(&parent) {
                Some(q) => q.clone(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

        let name = name.to_string_lossy().to_string();

        let path =
            if parent_path.is_empty() {
                name.clone()
            } else {
                format!(
                    "{}/{}",
                    parent_path,
                    name.to_string()
                )
            };

        let ino = self.get_inode(&path);

        let attr = FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 512,
            flags: 0,
        };

        let mut parent_token =
            if parent_path.is_empty() {
                ".".to_string()
            } else {
                parent_path.clone()
            };

        parent_token = crypto::make_token("oreore-key", &parent_token);
        let ciphertext = crypto::encrypt(&name);

        match server_api::add_index(
            &parent_token,
            &ciphertext,
        ) {
            Ok(_) => {
                println!("index updated");
            }
            Err(e) => {
                println!("index update failed: {}", e);
            }
        }

        let path_token = crypto::make_token("oreore-key", &path);
        match server_api::mkdir(
            &path_token,
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

        reply.entry(
            &TTL,
            &attr,
            0,
        );
    }

    fn unlink(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        reply: ReplyEmpty,
    ) {
        println!(
            "unlink(parent={}, name={:?})",
            parent,
            name,
        );

        let parent_path = match self.inode_to_query.get(&parent) {
            Some(q) => q.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let name = name.to_string_lossy().to_string();

        let path =
            if parent_path.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", parent_path, name)
            };

        let parent_token =
            if parent_path.is_empty() {
                crypto::make_token("oreore-key", ".")
            } else {
                crypto::make_token("oreore-key", &parent_path)
            };

        let path_token =
            crypto::make_token(
                "oreore-key",
                &path,
            );

        
        let url = format!(
            "http://192.168.11.8:2226/search?token={}",
            parent_token
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

        let mut enc_name = String::new();
        for enc in result.files {
            if crypto::decrypt(&enc) == name {
                enc_name = enc;
                break;
            }
        }
        println!("enc_name = {}", enc_name);

        match server_api::delete(
            &parent_token,
            &enc_name,
            &path_token,
        ) {
            Ok(_) => {}
            Err(e) => {
                println!("delete failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        }

        if let Some(ino) = self.query_to_inode.remove(&path) {
            self.inode_to_query.remove(&ino);
        }

        reply.ok();
    }

    fn rmdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        reply: ReplyEmpty,
    ) {
        println!(
            "rmdir(parent={}, name={:?})",
            parent,
            name,
        );

        let parent_path = match self.inode_to_query.get(&parent) {
            Some(q) => q.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let name = name.to_string_lossy().to_string();

        let path =
            if parent_path.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", parent_path, name)
            };

        let parent_token =
            if parent_path.is_empty() {
                crypto::make_token("oreore-key", ".")
            } else {
                crypto::make_token("oreore-key", &parent_path)
            };

        let path_token =
            crypto::make_token(
                "oreore-key",
                &path,
            );

        // ディレクトリ内が空か確認
        let url = format!(
            "http://192.168.11.8:2226/search?token={}",
            path_token,
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

        if !result.files.is_empty() {
            reply.error(libc::ENOTEMPTY);
            return;
        }

        let url = format!(
            "http://192.168.11.8:2226/search?token={}",
            parent_token
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

        let mut enc_name = String::new();
        for enc in result.files {
            if crypto::decrypt(&enc) == name {
                enc_name = enc;
                break;
            }
        }
        println!("enc_name = {}", enc_name);

        match server_api::delete(
            &parent_token,
            &enc_name,
            &path_token,
        ) {
            Ok(_) => {}
            Err(e) => {
                println!("delete failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        }

        if let Some(ino) = self.query_to_inode.remove(&path) {
            self.inode_to_query.remove(&ino);
        }

        reply.ok();
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        println!("setattr({})", ino);

        if let Some(new_size) = size {

            println!("truncate -> {}", new_size);

            let path =
                match self.inode_to_query.get(&ino) {
                    Some(q) => q.clone(),
                    None => {
                        reply.error(libc::ENOENT);
                        return;
                    }
                };

            let path_token =
                crypto::make_token(
                    "oreore-key",
                    &path,
                );

            let mut content =
                match server_api::download(&path_token) {
                    Ok(v) => v,
                    Err(_) => {
                        reply.error(libc::EIO);
                        return;
                    }
                };
                
            content.resize(new_size as usize, 0);

            let encrypted = crypto::encrypt_bytes(&content);

            match server_api::upload(
                &path_token,
                &encrypted,
            ) {
                Ok(_) => {}
                Err(_) => {
                    reply.error(libc::EIO);
                    return;
                }
            }
        }

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