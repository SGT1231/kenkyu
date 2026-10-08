use fuser::{
    MountOption,
};

use std::process::Command;
use std::str::FromStr;

use std::collections::HashMap;

use log::LevelFilter;

const ROOT_INO: u64 = 1;

mod crypto;
mod server_api;
mod myfs;
mod key_manager;
mod keyword_state;

#[cfg(test)]
mod forward_privacy_test;

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
                        log::info!("Found ssefs group ID: {}", gid);
                        return gid;
                    }
                }
            }
        }
        Err(e) => {
            log::error!("Failed to execute getent command: {}", e);
        }
    }
    
    // グループが見つからない場合、新しく作成する
    log::info!("Creating ssefs group...");
    let output = Command::new("sudo")
        .arg("groupadd")
        .arg("ssefs")
        .output();
    
    match output {
        Ok(output) => {
            if output.status.success() {
                log::info!("Successfully created ssefs group");
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
                                log::info!("New ssefs group ID: {}", gid);
                                return gid;
                            }
                        }
                    }
                }
            } else {
                let error_str = String::from_utf8_lossy(&output.stderr);
                log::error!("Failed to create ssefs group: {}", error_str);
            }
        }
        Err(e) => {
            log::error!("Failed to execute groupadd command: {}", e);
        }
    }
    
    // どちらも失敗した場合はデフォルト値を使用
    log::warn!("Using default group ID: 1001");
    1001
}

use myfs::MyFS;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mountpoint = args
        .get(1)
        .expect("Usage: ssefs <mountpoint> [off|error|warn|info|debug|trace]")
        .clone();
    let log_level = args
        .get(2)
        .map(|s| LevelFilter::from_str(s).unwrap_or(LevelFilter::Off))
        .unwrap_or(LevelFilter::Off);

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp(None)
        .init();

    // マスター鍵を初期化（.config/ssefs/master.key から読み込み or 生成）
    if let Err(e) = key_manager::init() {
        eprintln!("Failed to initialize master key: {}", e);
        std::process::exit(1);
    }

    // TDP 鍵対を初期化（.config/ssefs/tdp_private.pem / tdp_public.pem）
    if let Err(e) = key_manager::tdp_init() {
        eprintln!("Failed to initialize TDP key: {}", e);
        std::process::exit(1);
    }

    // ssefsグループのIDを取得
    let ssefs_gid = get_ssefs_group_id();

    let dir_map = keyword_state::DirMap::load_or_create();

    fuser::mount2(
        MyFS {
            inode_to_query: HashMap::from([
                (ROOT_INO, "".to_string()),
            ]),
            query_to_inode: HashMap::from([
                ("".to_string(), ROOT_INO),
            ]),
            next_inode: 2,
            ssefs_gid: ssefs_gid,
            dir_map,
            search_cache: HashMap::new(),
        },
        mountpoint,
        &[MountOption::FSName("ssefs".into())],
    )
    .unwrap();
}
