
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
    pub ssefs_gid: u32,  // ssefsグループID
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
            gid: self.ssefs_gid, // ssefsグループID
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
            self.ssefs_gid,
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
                self.ssefs_gid,
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
            gid: self.ssefs_gid, // ssefsグループID
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
            self.ssefs_gid,
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
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        println!("setattr({})", ino);

        let path = match self.inode_to_query.get(&ino) {
            Some(q) => q.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // サーバーに属性変更を通知
        let path_token = crypto::make_token("oreore-key", &path);
        
        // 時間系のオプションをUNIX時間に変換
        let atime_unix = atime.map(|t| match t {
            fuser::TimeOrNow::SpecificTime(st) => st.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
            fuser::TimeOrNow::Now => SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        });
        
        let mtime_unix = mtime.map(|t| match t {
            fuser::TimeOrNow::SpecificTime(st) => st.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
            fuser::TimeOrNow::Now => SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        });
        
        let ctime_unix = ctime.map(|st| st.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64);

        if let Err(e) = server_api::setattr(
            &path_token,
            mode,
            uid,
            gid,
            atime_unix,
            mtime_unix,
            ctime_unix,
            size,
        ) {
            println!("setattr failed: {}", e);
            reply.error(libc::EIO);
            return;
        }

        // ファイルサイズ変更処理（古い方法での互換性維持）
        if let Some(new_size) = size {
            println!("truncate -> {}", new_size);

            let path_token = crypto::make_token("oreore-key", &path);

            let mut content = match server_api::download(&path_token) {
                Ok(v) => v,
                Err(_) => {
                    reply.error(libc::EIO);
                    return;
                }
            };
                
            content.resize(new_size as usize, 0);

            let encrypted = crypto::encrypt_bytes(&content);

            match server_api::upload(&path_token, &encrypted, self.ssefs_gid) {
                Ok(_) => {}
                Err(_) => {
                    reply.error(libc::EIO);
                    return;
                }
            }
        }

        // ファイルの属性情報を取得
        let path_token = crypto::make_token("oreore-key", &path);
        let stat_result: server_api::StatResult = match reqwest::blocking::get(&format!(
            "http://192.168.11.8:2226/stat?token={}",
            path_token
        )) {
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

        let kind = if stat_result.is_dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        };

        let attr = FileAttr {
            ino,
            size: stat_result.size,
            blocks: stat_result.blocks,
            atime: UNIX_EPOCH + Duration::from_secs(stat_result.atime as u64),
            mtime: UNIX_EPOCH + Duration::from_secs(stat_result.mtime as u64),
            ctime: UNIX_EPOCH + Duration::from_secs(stat_result.ctime as u64),
            crtime: UNIX_EPOCH + Duration::from_secs(stat_result.ctime as u64),
            kind,
            perm: stat_result.mode as u16,
            nlink: stat_result.nlink,
            uid: stat_result.uid,
            gid: stat_result.gid,
            rdev: stat_result.rdev,
            blksize: stat_result.blksize,
            flags: 0,
        };
        
        reply.attr(&TTL, &attr);
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        println!(
            "rename(parent={}, name={:?}, newparent={}, newname={:?})",
            parent,
            name,
            newparent,
            newname,
        );

        //
        // 1. 移動元・移動先のパスを取得
        //
        let old_parent_path = match self.inode_to_query.get(&parent) {
            Some(q) => q.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let new_parent_path = match self.inode_to_query.get(&newparent) {
            Some(q) => q.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let old_name = name.to_string_lossy().to_string();
        let new_name = newname.to_string_lossy().to_string();

        let old_path = if old_parent_path.is_empty() {
            old_name.clone()
        } else {
            format!("{}/{}", old_parent_path, old_name)
        };

        let new_path = if new_parent_path.is_empty() {
            new_name.clone()
        } else {
            format!("{}/{}", new_parent_path, new_name)
        };

        //
        // 2. 移動元ディレクトリのインデックスを検索し、old_ciphertext を取得
        //
        let old_parent_token = if old_parent_path.is_empty() {
            crypto::make_token("oreore-key", ".")
        } else {
            crypto::make_token("oreore-key", &old_parent_path)
        };

        let url = format!(
            "http://192.168.11.8:2226/search?token={}",
            old_parent_token
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

        let mut old_ciphertext = String::new();
        for enc in &result.files {
            if crypto::decrypt(enc) == old_name {
                old_ciphertext = enc.clone();
                break;
            }
        }

        if old_ciphertext.is_empty() {
            reply.error(libc::ENOENT);
            return;
        }

        //
        // 3. 移動元ディレクトリから削除
        //
        match server_api::remove_index(&old_parent_token, &old_ciphertext) {
            Ok(_) => {
                println!("removed from old parent index");
            }
            Err(e) => {
                println!("remove_index failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        }

        //
        // 4. 移動先ディレクトリへ登録
        //
        let new_parent_token = if new_parent_path.is_empty() {
            crypto::make_token("oreore-key", ".")
        } else {
            crypto::make_token("oreore-key", &new_parent_path)
        };

        let new_ciphertext = crypto::encrypt(&new_name);

        match server_api::add_index(&new_parent_token, &new_ciphertext) {
            Ok(_) => {
                println!("added to new parent index");
            }
            Err(e) => {
                println!("add_index failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        }

        //
        // 5. 対象がディレクトリかどうか確認
        //
        let old_path_token = crypto::make_token("oreore-key", &old_path);

        let url = format!(
            "http://192.168.11.8:2226/stat?token={}",
            old_path_token
        );

        let stat_result: server_api::StatResult = match reqwest::blocking::get(&url) {
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

        let is_dir = stat_result.is_dir;

        //
        // 6. 実データをリネーム
        //
        let new_path_token = crypto::make_token("oreore-key", &new_path);

        match server_api::rename(&old_path_token, &new_path_token, is_dir) {
            Ok(_) => {
                println!("server rename ok");
            }
            Err(e) => {
                println!("server rename failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        }

        //
        // 7. FUSE側の管理情報を更新
        //    old_path から始まるすべてのパスを new_path に置換
        //
        let old_prefix = format!("{}/", old_path);
        let new_prefix = format!("{}/", new_path);

        // まず old_path 自身を更新
        if let Some(ino) = self.query_to_inode.remove(&old_path) {
            self.query_to_inode.insert(new_path.clone(), ino);
            self.inode_to_query.insert(ino, new_path.clone());
        }

        // 子孫のパスも更新
        let entries_to_update: Vec<(String, u64)> = self
            .query_to_inode
            .iter()
            .filter(|(path, _)| path.starts_with(&old_prefix))
            .map(|(path, &ino)| (path.clone(), ino))
            .collect();

        for (old_child_path, ino) in entries_to_update {
            let new_child_path = old_child_path.replacen(&old_prefix, &new_prefix, 1);
            self.query_to_inode.remove(&old_child_path);
            self.query_to_inode.insert(new_child_path.clone(), ino);
            self.inode_to_query.insert(ino, new_child_path);
        }

        reply.ok();
    }
}
