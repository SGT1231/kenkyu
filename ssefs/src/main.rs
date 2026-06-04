use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem,
    MountOption, ReplyAttr, ReplyDirectory,
    Request,
};

use serde::Deserialize;

use fuser::ReplyEntry;
use std::ffi::OsStr;

use std::collections::HashMap;

const TTL: Duration = Duration::from_secs(1);

const ROOT_INO: u64 = 1;

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
            let kind2 = if query.ends_with(".txt") {
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
            perm: 0o755,
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
        let url = format!(
            "http://192.168.11.8:2226/search?token={}",
            query
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

        for file in result.files {
            let child_query = format!("{}/{}", query, file);
            let child_ino = self.get_inode(&child_query);

            let _ = reply.add(
                child_ino,
                1,
                FileType::RegularFile,
                file,
            );
        }

        println!("child_query = {}", ino);
        reply.ok();
        return;
    }
}

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