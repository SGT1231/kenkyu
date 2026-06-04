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
const FRUIT_INO: u64 = 2;

#[derive(Deserialize)]
struct SearchResult {
    files: Vec<String>,
}

struct MyFS {
    dirs: HashMap<u64, String>,
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

        if parent == ROOT_INO
            && name.to_str() == Some("fruit")
        {
            let attr = FileAttr {
                ino: FRUIT_INO,
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

            reply.entry(&TTL, &attr, 0);
            return;
        }

        if parent == FRUIT_INO
            && name.to_str() == Some("fruit")
        {
            let attr = FileAttr {
                ino: 3,
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

            reply.entry(&TTL, &attr, 0);
            return;
        }

        reply.error(libc::ENOENT);
    }

    fn getattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        reply: ReplyAttr,
    ) {
        println!("getattr({})", ino);
        let attr = match ino {

            ROOT_INO => FileAttr {
                ino: ROOT_INO,
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
            },

            FRUIT_INO => FileAttr {
                ino: FRUIT_INO,
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
            },

            3 => FileAttr {
                ino: 3,
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
            },

            _ => {
                reply.error(libc::ENOENT);
                return;
            }
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

        println!("readdir({}, {})", ino, _offset);

        if _offset != 0 {
            reply.ok();
            return;
        }

        if ino == ROOT_INO {

            let _ = reply.add(ROOT_INO, 1, FileType::Directory, ".");
            let _ = reply.add(ROOT_INO, 2, FileType::Directory, "..");
            let _ = reply.add(FRUIT_INO, 3, FileType::Directory, "fruit");

            reply.ok();
            return;
        }

        if ino == FRUIT_INO {

            let _ = reply.add(FRUIT_INO, 1, FileType::Directory, ".");
            let _ = reply.add(ROOT_INO, 2, FileType::Directory, "..");

            // さらに fruit を生やす
            let _ = reply.add(3, 3, FileType::Directory, "fruit");

            reply.ok();
            return;
        }

        if ino == 3 {

            let result: SearchResult =
                reqwest::blocking::get(
                    "http://192.168.11.8:2226/search?token=fruit/fruit"
                )
                .unwrap()
                .json()
                .unwrap();

            let _ = reply.add(FRUIT_INO, 1, FileType::Directory, ".");
            let _ = reply.add(ROOT_INO, 2, FileType::Directory, "..");

            let mut ino_num = 100;

            for file in result.files {

                let _ = reply.add(
                    ino_num,
                    ino_num as i64,
                    FileType::RegularFile,
                    file,
                );

                ino_num += 1;
            }

            reply.ok();
            return;
        }

        reply.error(libc::ENOENT);
    }
}

fn main() {

    let mountpoint = std::env::args()
        .nth(1)
        .expect("mountpoint");

    fuser::mount2(
        MyFS {
            dirs: HashMap::new(),
        },
        mountpoint,
        &[MountOption::FSName("ssefs".into())],
    )
    .unwrap();
}