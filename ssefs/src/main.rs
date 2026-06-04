use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem,
    MountOption, ReplyAttr, ReplyDirectory,
    Request,
};

use serde::Deserialize;

const TTL: Duration = Duration::from_secs(1);

const ROOT_INO: u64 = 1;
const FRUIT_INO: u64 = 2;

#[derive(Deserialize)]
struct SearchResult {
    files: Vec<String>,
}

struct MyFS;

impl Filesystem for MyFS {

    fn getattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: Option<u64>,
        reply: ReplyAttr,
    ) {
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
        offset: i64,
        mut reply: ReplyDirectory,
    ) {

        if ino == ROOT_INO {

            reply.add(ROOT_INO, 1, FileType::Directory, ".");
            reply.add(ROOT_INO, 2, FileType::Directory, "..");
            reply.add(FRUIT_INO, 3, FileType::Directory, "fruit");

            reply.ok();
            return;
        }

        if ino == FRUIT_INO {

            let result: SearchResult =
                reqwest::blocking::get(
                    "http://192.168.11.8:8080/search?token=fruit"
                )
                .unwrap()
                .json()
                .unwrap();

            reply.add(FRUIT_INO, 1, FileType::Directory, ".");
            reply.add(ROOT_INO, 2, FileType::Directory, "..");

            let mut ino_num = 100;

            for file in result.files {

                reply.add(
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
        MyFS,
        mountpoint,
        &[MountOption::FSName("ssefs".into())],
    )
    .unwrap();
}