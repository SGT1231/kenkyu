
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
use crate::keyword_state::{DirMap, KeywordState};
use crate::key_manager;

const TTL: Duration = Duration::from_secs(0);

pub struct MyFS {
    pub next_inode: u64,
    pub inode_to_query: HashMap<u64, String>,
    pub query_to_inode: HashMap<String, u64>,
    pub ssefs_gid: u32,
    pub dir_map: DirMap,
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

    /// 指定ディレクトリパスに対する暗号化エントリ名を検索・復号して返す
    fn search_directory(&mut self, path: &str) -> Result<Vec<String>, i32> {
        let keyword_id = match self.dir_map.path_to_keyword.get(path) {
            Some(kw) => kw.clone(),
            None => return Ok(Vec::new()), // キーワード未登録 → 空ディレクトリ
        };

        let state = match self.dir_map.get_state(&keyword_id) {
            Some(s) => s.clone(),
            None => return Ok(Vec::new()),
        };

        if state.counter == 0 {
            return Ok(Vec::new());
        }

        let master_key = key_manager::get_key();
        let dk = crypto::derive_dk(master_key, &keyword_id);

        let result = match server_api::search(&state.latest_st, &hex::encode(dk), state.counter as u64) {
            Ok(r) => r,
            Err(_) => return Err(libc::EIO),
        };

        let mut names = Vec::new();
        for encrypted_name in &result.files {
            let plain = crypto::decrypt(encrypted_name);
            if !plain.is_empty() {
                names.push(plain);
            }
        }
        println!(
            "[search_directory] path={}, keyword_id={}, counter={}",
            path,
            keyword_id,
            state.counter
        );

        println!(
            "[search_directory] latest_st={}",
            state.latest_st
        );

        println!(
            "[search_directory] server returned {} files",
            result.files.len()
        );

        for (i, encrypted_name) in result.files.iter().enumerate() {
            let plain = crypto::decrypt(encrypted_name);
            println!(
                "[search_directory] result[{}] = {:?}",
                i,
                plain
            );
        }

        Ok(names)
    }

    /// 指定ディレクトリの ST を1世代進め、UT を生成して返す
    /// 返り値: (keyword_id, ut)
    fn advance_st_and_get_ut(&mut self, path: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
        let keyword_id = self.dir_map.get_or_create_keyword(path);
        let master_key = key_manager::get_key();
        let n = key_manager::get_tdp_n();
        let d = key_manager::get_tdp_d();

        let keyword_id_clone = keyword_id.clone();
        let mut state = self.dir_map.get_state(&keyword_id_clone)
            .cloned()
            .unwrap_or(KeywordState { counter: 0, latest_st: String::new() });

        let new_st = if state.counter == 0 {
            crypto::st_init(master_key, &keyword_id, &n)
        } else {
            let current = crypto::base64_to_biguint(&state.latest_st)
                .ok_or("Invalid latest_st")?;
            crypto::st_next(&current, &d, &n)
        };

        let dk = crypto::derive_dk(master_key, &keyword_id);
        let ut = crypto::derive_ut(&dk, &new_st);

        state.latest_st = crypto::biguint_to_base64(&new_st);
        state.counter += 1;

        self.dir_map.update_state(&keyword_id, state);
        self.dir_map.save()?;

        Ok((keyword_id, ut))
    }

    /// 指定ディレクトリ内から target_name に一致するエントリの UT を探索して返す
    fn find_ut_for_entry(&mut self, parent_path: &str, target_name: &str) -> Result<Option<String>, i32> {
        let keyword_id = match self.dir_map.path_to_keyword.get(parent_path) {
            Some(kw) => kw.clone(),
            None => return Ok(None),
        };
        let state = match self.dir_map.get_state(&keyword_id) {
            Some(s) => s.clone(),
            None => return Ok(None),
        };
        if state.counter == 0 {
            return Ok(None);
        }

        let master_key = key_manager::get_key();
        let dk = crypto::derive_dk(master_key, &keyword_id);

        let result = match server_api::search(&state.latest_st, &hex::encode(dk), state.counter as u64) {
            Ok(r) => r,
            Err(_) => return Err(libc::EIO),
        };

        let ciphertext = crypto::encrypt(target_name);
        for enc in &result.files {
            if enc == &ciphertext {
                // server_api::search はファイル名を返すだけなので UT は直接的に返されない。
                // Phase 3 では O(counter) 探索でクライアント側でも UT を再導出できる。
                // ここでは ut_cache を信頼し、なければ cache miss として server 側の
                // get_by_ut を使う方針は採用しない。
                // 代わりに、client 側で ST chain をたどり UT を再計算して特定する。
                let n = key_manager::get_tdp_n();
                let e = key_manager::get_tdp_e();
                let mut st = crypto::base64_to_biguint(&state.latest_st)
                    .ok_or(libc::EIO)?;
                // 最新から逆方向（counter 分）たどる
                // サーバ側は eval(st^e) で過去へ進む。クライアントも同じ。
                println!("counter = {}", state.counter);
                for _ in 0..state.counter {
                    let ut = crypto::derive_ut(&dk, &st);
                    // この UT に対応するエントリがサーバにあるか get_by_ut で確認
                    match server_api::get_by_ut(&ut) {
                        Ok(Some(val)) if val == *enc => return Ok(Some(ut)),
                        _ => {}
                    }
                    st = st.modpow(&e, &n); // TDP eval: 過去へ
                }
                return Ok(None);
            }
        }
        Ok(None)
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

        let target_name = name.to_string_lossy().to_string();

        let names = match self.search_directory(&parent_path) {
            Ok(n) => n,
            Err(e) => {
                reply.error(e);
                return;
            }
        };

        let mut found = false;
        for plain_name in &names {
            if *plain_name == target_name {
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
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        println!("readdir({}, offset={})", ino, offset);

        // inode → query
        let path = match self.inode_to_query.get(&ino) {
            Some(q) => q.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let names = match self.search_directory(&path) {
            Ok(n) => n,
            Err(e) => {
                reply.error(e);
                return;
            }
        };

        // 返すエントリを組み立てる（offset ベースの再開に対応）
        let mut entries: Vec<(u64, FileType, String)> = Vec::new();
        entries.push((ino, FileType::Directory, ".".to_string()));

        let parent_path = match path.rfind('/') {
            Some(pos) => &path[..pos],
            None => "",
        };
        let parent_ino = self.get_inode(parent_path);
        println!("parent_ino = {}", parent_ino);
        entries.push((parent_ino, FileType::Directory, "..".to_string()));

        for filename in names {
            let child_path = if path.is_empty() {
                filename.clone()
            } else {
                format!("{}/{}", path, filename)
            };
            let child_ino = self.get_inode(&child_path);

            let path_token = crypto::make_token("oreore-key", &child_path);
            let stat_url = format!(
                "http://192.168.11.8:2226/stat?token={}",
                path_token
            );
            let file_type = match reqwest::blocking::get(&stat_url) {
                Ok(res) => match res.json::<server_api::StatResult>() {
                    Ok(stat) => if stat.is_dir { FileType::Directory } else { FileType::RegularFile },
                    Err(_) => FileType::RegularFile,
                },
                Err(_) => FileType::RegularFile,
            };

            entries.push((child_ino, file_type, filename));
        }

        // offset 以降のエントリを返す。
        // reply.add が true を返したらバッファがいっぱいなので中断する。
        let mut added = 0usize;
        for (i, (entry_ino, entry_type, name)) in entries.iter().enumerate().skip(offset as usize) {
            let next_offset = (i + 1) as i64;
            if reply.add(*entry_ino, next_offset, *entry_type, name) {
                println!("readdir buffer full at offset {}", next_offset);
                break;
            }
            added += 1;
        }

        println!(
            "readdir entries={}, added={}, started_at_offset={}",
            entries.len(),
            added,
            offset
        );

        reply.ok();
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

        let ciphertext = crypto::encrypt(&name);

        let (_keyword_id, ut) = match self.advance_st_and_get_ut(&parent_path) {
            Ok((kw, ut)) => (kw, ut),
            Err(e) => {
                println!("advance ST failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        };

        match server_api::add_index(&ut, &ciphertext) {
            Ok(_) => {
                println!("index updated with ut={}", ut);
            }
            Err(e) => {
                println!("add_index failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        }

        self.dir_map.add_ut_cache(&parent_path, &ciphertext, &ut);
        if let Err(e) = self.dir_map.save() {
            println!("dir_map save failed: {}", e);
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

        // 新しいディレクトリ自身の keyword_id を生成
        self.dir_map.get_or_create_keyword(&path);

        // 親ディレクトリのインデックスに新しいディレクトリ名を登録
        let ciphertext = crypto::encrypt(&name);
        let (_keyword_id, ut) = match self.advance_st_and_get_ut(&parent_path) {
            Ok((kw, ut)) => (kw, ut),
            Err(e) => {
                println!("advance ST failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        };

        match server_api::add_index(&ut, &ciphertext) {
            Ok(_) => {
                println!("index updated with ut={}", ut);
            }
            Err(e) => {
                println!("index update failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        }

        self.dir_map.add_ut_cache(&parent_path, &ciphertext, &ut);
        if let Err(e) = self.dir_map.save() {
            println!("dir_map save failed: {}", e);
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

        let path_token =
            crypto::make_token(
                "oreore-key",
                &path,
            );

        let ut = match self.find_ut_for_entry(&parent_path, &name) {
            Ok(Some(ut)) => ut,
            Ok(None) => {
                println!("ut not found for {}", name);
                reply.error(libc::ENOENT);
                return;
            }
            Err(e) => {
                reply.error(e);
                return;
            }
        };

        let ciphertext = crypto::encrypt(&name);

        match server_api::remove_index(&ut) {
            Ok(_) => {
                println!("remove_index ok for ut={}", ut);
            }
            Err(e) => {
                println!("remove_index failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        }

        self.dir_map.remove_ut_cache(&parent_path, &ciphertext);
        if let Err(e) = self.dir_map.save() {
            println!("dir_map save failed: {}", e);
        }

        match server_api::delete_storage(&path_token) {
            Ok(_) => {}
            Err(e) => {
                println!("delete_storage failed: {}", e);
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

        let path_token =
            crypto::make_token(
                "oreore-key",
                &path,
            );

        // ディレクトリ内が空か確認
        let children = match self.search_directory(&path) {
            Ok(files) => files,
            Err(e) => {
                reply.error(e);
                return;
            }
        };

        if !children.is_empty() {
            reply.error(libc::ENOTEMPTY);
            return;
        }

        let ut = match self.find_ut_for_entry(&parent_path, &name) {
            Ok(Some(ut)) => ut,
            Ok(None) => {
                println!("ut not found for {}", name);
                reply.error(libc::ENOENT);
                return;
            }
            Err(e) => {
                reply.error(e);
                return;
            }
        };

        let ciphertext = crypto::encrypt(&name);

        match server_api::remove_index(&ut) {
            Ok(_) => {
                println!("remove_index ok for ut={}", ut);
            }
            Err(e) => {
                println!("remove_index failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        }

        self.dir_map.remove_ut_cache(&parent_path, &ciphertext);
        self.dir_map.remove_path(&path);
        if let Err(e) = self.dir_map.save() {
            println!("dir_map save failed: {}", e);
        }

        match server_api::delete_storage(&path_token) {
            Ok(_) => {}
            Err(e) => {
                println!("delete_storage failed: {}", e);
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
        // 2. 対象がディレクトリかどうか確認
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

        // ディレクトリの cross-directory move は未サポート
        if is_dir && old_parent_path != new_parent_path {
            reply.error(libc::EXDEV);
            return;
        }

        //
        // 3. 移動元ディレクトリからインデックス削除
        //
        let old_ut = match self.find_ut_for_entry(&old_parent_path, &old_name) {
            Ok(Some(ut)) => ut,
            Ok(None) => {
                println!("ut not found for {}", old_name);
                reply.error(libc::ENOENT);
                return;
            }
            Err(e) => {
                reply.error(e);
                return;
            }
        };

        match server_api::remove_index(&old_ut) {
            Ok(_) => {
                println!("removed from old parent index");
            }
            Err(e) => {
                println!("remove_index failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        }

        let old_ciphertext = crypto::encrypt(&old_name);
        self.dir_map.remove_ut_cache(&old_parent_path, &old_ciphertext);

        //
        // 4. 移動先ディレクトリへ登録
        //
        let new_ciphertext = crypto::encrypt(&new_name);

        let (_keyword_id, new_ut) = match self.advance_st_and_get_ut(&new_parent_path) {
            Ok((kw, ut)) => (kw, ut),
            Err(e) => {
                println!("advance ST failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        };

        match server_api::add_index(&new_ut, &new_ciphertext) {
            Ok(_) => {
                println!("added to new parent index");
            }
            Err(e) => {
                println!("add_index failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        }

        self.dir_map.add_ut_cache(&new_parent_path, &new_ciphertext, &new_ut);
        if let Err(e) = self.dir_map.save() {
            println!("dir_map save failed: {}", e);
        }

        //
        // 5. ディレクトリ自身の rename 時は DirMap も更新
        //
        if is_dir {
            self.dir_map.rename_path(&old_path, &new_path);
            if let Err(e) = self.dir_map.save() {
                println!("dir_map save failed: {}", e);
            }
        }

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
