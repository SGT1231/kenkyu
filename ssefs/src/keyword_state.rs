use std::collections::HashMap;
use std::fs;
use std::path::Path;
use serde::{Serialize, Deserialize};

const DIR_MAP_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../.config/ssefs/dir_map.json");

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeywordState {
    pub counter: u32,
    pub latest_st: String, // BigUint を Base64 エンコードしたもの
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DirMap {
    pub path_to_keyword: HashMap<String, String>,
    pub keyword_to_state: HashMap<String, KeywordState>,
    /// 削除・rename 時の対象 UT 特定を高速化するためのキャッシュ
    /// key = "parent_path/ciphertext", value = ut
    pub ut_cache: HashMap<String, String>,
}

impl DirMap {
    pub fn load_or_create() -> Self {
        let path = Path::new(DIR_MAP_FILE);
        if path.exists() {
            let contents = fs::read_to_string(path).unwrap_or_default();
            if contents.trim().is_empty() {
                Self::default()
            } else {
                serde_json::from_str(&contents).unwrap_or_default()
            }
        } else {
            Self::default()
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = Path::new(DIR_MAP_FILE);
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// path に対応する keyword_id を取得または新規生成する
    pub fn get_or_create_keyword(&mut self, path: &str) -> String {
        if let Some(kw) = self.path_to_keyword.get(path) {
            return kw.clone();
        }
        let keyword_id = format!("kw_{:016x}", rand::random::<u64>());
        self.path_to_keyword.insert(path.to_string(), keyword_id.clone());
        let state = KeywordState {
            counter: 0,
            latest_st: String::new(),
        };
        self.keyword_to_state.insert(keyword_id.clone(), state);
        keyword_id
    }

    pub fn get_state(&self, keyword_id: &str) -> Option<&KeywordState> {
        self.keyword_to_state.get(keyword_id)
    }

    pub fn update_state(&mut self, keyword_id: &str, state: KeywordState) {
        self.keyword_to_state.insert(keyword_id.to_string(), state);
    }

    pub fn rename_path(&mut self, old_path: &str, new_path: &str) {
        // old_path 自身の keyword_id を移動
        if let Some(keyword_id) = self.path_to_keyword.remove(old_path) {
            self.path_to_keyword.insert(new_path.to_string(), keyword_id);
        }

        // 子孫ディレクトリの keyword マッピングも更新
        let old_prefix = format!("{}/", old_path);
        let new_prefix = format!("{}/", new_path);
        let keys_to_rename: Vec<String> = self
            .path_to_keyword
            .keys()
            .filter(|k| k.starts_with(&old_prefix))
            .cloned()
            .collect();

        for key in keys_to_rename {
            let suffix = &key[old_prefix.len()..];
            let new_key = format!("{}{}", new_prefix, suffix);
            if let Some(keyword_id) = self.path_to_keyword.remove(&key) {
                self.path_to_keyword.insert(new_key, keyword_id);
            }
        }

        // ut_cache 内の子孫エントリもパスを更新
        let cache_keys_to_rename: Vec<String> = self
            .ut_cache
            .keys()
            .filter(|k| k.starts_with(&old_prefix))
            .cloned()
            .collect();

        for key in cache_keys_to_rename {
            let suffix = &key[old_prefix.len()..];
            let new_key = format!("{}{}", new_prefix, suffix);
            if let Some(ut) = self.ut_cache.remove(&key) {
                self.ut_cache.insert(new_key, ut);
            }
        }
    }

    pub fn remove_path(&mut self, path: &str) {
        if let Some(keyword_id) = self.path_to_keyword.remove(path) {
            self.keyword_to_state.remove(&keyword_id);
        }
    }

    pub fn add_ut_cache(&mut self, parent_path: &str, ciphertext: &str, ut: &str) {
        let key = format!("{}/{}", parent_path, ciphertext);
        self.ut_cache.insert(key, ut.to_string());
    }

    pub fn get_ut_cache(&self, parent_path: &str, ciphertext: &str) -> Option<&String> {
        let key = format!("{}/{}", parent_path, ciphertext);
        self.ut_cache.get(&key)
    }

    pub fn remove_ut_cache(&mut self, parent_path: &str, ciphertext: &str) {
        let key = format!("{}/{}", parent_path, ciphertext);
        self.ut_cache.remove(&key);
    }
}
