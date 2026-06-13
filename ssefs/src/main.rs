use fuser::{
    MountOption,
};

use std::collections::HashMap;

const ROOT_INO: u64 = 1;

mod crypto;
mod server_api;
mod myfs;

use myfs::MyFS;

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