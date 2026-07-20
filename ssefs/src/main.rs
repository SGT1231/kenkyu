use fuser::{
    MountOption,
};

use std::process::Command;
use std::str::FromStr;

use std::collections::HashMap;

const ROOT_INO: u64 = 1;

mod crypto;
mod server_api;
mod myfs;

// ssefsグループのIDを取得する関数
fn get_ssefs_group_id() -> u32 {
    // getent group ssefs コマンドを実行してグループ情報を取得
    let output = Command::new("getent")
        .arg("group")
        .arg("ssefs")
        .output();
    
    match output {
        Ok(output) => {
            if output.status.success() {
                // 成功した場合、出力からグループIDを抽出
                let output_str = String::from_utf8_lossy(&output.stdout);
                let parts: Vec<&str> = output_str.split(':').collect();
                if parts.len() >= 3 {
                    // グループIDは3番目の要素
                    if let Ok(gid) = u32::from_str(parts[2]) {
                        println!("Found ssefs group ID: {}", gid);
                        return gid;
                    }
                }
            }
        }
        Err(e) => {
            println!("Failed to execute getent command: {}", e);
        }
    }
    
    // グループが見つからない場合、新しく作成する
    println!("Creating ssefs group...");
    let output = Command::new("sudo")
        .arg("groupadd")
        .arg("ssefs")
        .output();
    
    match output {
        Ok(output) => {
            if output.status.success() {
                println!("Successfully created ssefs group");
                // 再度グループIDを取得
                let output = Command::new("getent")
                    .arg("group")
                    .arg("ssefs")
                    .output();
                
                if let Ok(output) = output {
                    if output.status.success() {
                        let output_str = String::from_utf8_lossy(&output.stdout);
                        let parts: Vec<&str> = output_str.split(':').collect();
                        if parts.len() >= 3 {
                            if let Ok(gid) = u32::from_str(parts[2]) {
                                println!("New ssefs group ID: {}", gid);
                                return gid;
                            }
                        }
                    }
                }
            } else {
                let error_str = String::from_utf8_lossy(&output.stderr);
                println!("Failed to create ssefs group: {}", error_str);
            }
        }
        Err(e) => {
            println!("Failed to execute groupadd command: {}", e);
        }
    }
    
    // どちらも失敗した場合はデフォルト値を使用
    println!("Using default group ID: 1001");
    1001
}

use myfs::MyFS;

fn main() {
    // ssefsグループのIDを取得
    let ssefs_gid = get_ssefs_group_id();
    
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
            ssefs_gid: ssefs_gid,  // グループIDをMyFSに渡す
        },
        mountpoint,
        &[MountOption::FSName("ssefs".into())],
    )
    .unwrap();
}
