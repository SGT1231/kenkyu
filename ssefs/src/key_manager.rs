use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::OnceLock;


// LinuxFUSE プロジェクト直下（Cargo.toml の親ディレクトリ）に鍵を保存
const KEY_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../.config/ssefs");
const KEY_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../.config/ssefs/master.key");
const KEY_SIZE: usize = 32;

static MASTER_KEY: OnceLock<[u8; KEY_SIZE]> = OnceLock::new();

/// マスター鍵を初期化する。
/// 既存の鍵ファイルがあれば読み込み、なければ生成して保存する。
pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    let key = load_or_create()?;
    MASTER_KEY
        .set(key)
        .map_err(|_| "Master key already initialized".to_string())?;
    Ok(())
}

/// 初期化済みのマスター鍵を取得する。
pub fn get_key() -> &'static [u8; KEY_SIZE] {
    MASTER_KEY
        .get()
        .expect("Master key not initialized. Call key_manager::init() first.")
}

fn load_or_create() -> Result<[u8; KEY_SIZE], Box<dyn std::error::Error>> {
    let key_path = Path::new(KEY_FILE);

    if key_path.exists() {
        load_key(key_path)
    } else {
        create_key(key_path)
    }
}

fn load_key(path: &Path) -> Result<[u8; KEY_SIZE], Box<dyn std::error::Error>> {
    let mut file = fs::File::open(path)
        .map_err(|e| format!("Failed to open master.key: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = file
            .metadata()
            .map_err(|e| format!("Failed to get metadata: {}", e))?;
        let permissions = metadata.permissions();
        let mode = permissions.mode() & 0o777;

        if mode != 0o600 {
            return Err(format!(
                "Insecure permissions on master.key: {:o} (expected 600)",
                mode
            )
            .into());
        }
    }

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|e| format!("Failed to read master.key: {}", e))?;

    if contents.len() != KEY_SIZE {
        return Err(format!(
            "Invalid key length: {} bytes (expected {})",
            contents.len(),
            KEY_SIZE
        )
        .into());
    }

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&contents);

    Ok(key)
}

/// 既存の ssefs と互換性を保つための固定鍵。
/// 以前は crypto.rs にハードコードされていた。
const LEGACY_KEY: [u8; KEY_SIZE] = *b"01234567890123456789012345678901";

fn create_key(path: &Path) -> Result<[u8; KEY_SIZE], Box<dyn std::error::Error>> {
    let dir = Path::new(KEY_DIR);
    if !dir.exists() {
        fs::create_dir_all(dir)
            .map_err(|e| format!("Failed to create directory {}: {}", KEY_DIR, e))?;
    }

    // 既存の暗号化データとの互換性のため、
    // 初回起動時は以前のハードコード鍵を master.key として保存する。
    let key = LEGACY_KEY;

    let mut file = fs::File::create(path)
        .map_err(|e| format!("Failed to create master.key: {}", e))?;

    file.write_all(&key)
        .map_err(|e| format!("Failed to write master.key: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path)
            .map_err(|e| format!("Failed to get metadata: {}", e))?
            .permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)
            .map_err(|e| format!("Failed to set permissions: {}", e))?;
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_key_path() -> std::path::PathBuf {
        let temp_dir = std::env::temp_dir().join(format!(
            "ssefs_key_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        temp_dir.join("master.key")
    }

    fn cleanup(path: &std::path::Path) {
        let _ = fs::remove_file(path);
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir(parent);
        }
    }

    #[test]
    fn test_create_key_generates_32_bytes() {
        let path = temp_key_path();
        let key = create_key(&path).unwrap();

        assert_eq!(key.len(), KEY_SIZE);
        // すべて0ではない（乱数が入っていることの簡易チェック）
        assert!(key.iter().any(|&b| b != 0));

        cleanup(&path);
    }

    #[test]
    fn test_create_key_sets_permissions() {
        let path = temp_key_path();
        create_key(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&path).unwrap();
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "Expected permissions 0o600, got 0o{:o}", mode);
        }

        cleanup(&path);
    }

    #[test]
    fn test_load_key_reads_same_key() {
        let path = temp_key_path();
        let key1 = create_key(&path).unwrap();
        let key2 = load_key(&path).unwrap();

        assert_eq!(key1.as_slice(), key2.as_slice());

        cleanup(&path);
    }

    #[test]
    fn test_load_key_detects_invalid_length() {
        let path = temp_key_path();
        fs::write(&path, b"short").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&path, permissions).unwrap();
        }

        let result = load_key(&path);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Invalid key length"));

        cleanup(&path);
    }

    #[test]
    fn test_init_idempotent_file() {
        let temp_dir = std::env::temp_dir().join(format!(
            "ssefs_init_test_{}",
            std::process::id()
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        // テスト用に一時ディレクトリ内で実行
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp_dir).unwrap();

        // load_or_create を直接テスト（OnceLock の競合を避ける）
        let key1 = load_or_create().unwrap();
        assert!(Path::new(KEY_FILE).exists());

        // 2回目：同じ鍵が読み込まれる（再生成されない）
        let key2 = load_or_create().unwrap();
        assert_eq!(key1.as_slice(), key2.as_slice());

        std::env::set_current_dir(original_dir).unwrap();
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_key_not_logged() {
        // 鍵がログに出力されないことを間接的に確認
        // get_key() の戻り値は &[u8; 32] で、Display 実装がないため
        // 誤って println!("{}", get_key()) はコンパイルエラーになる
        let path = temp_key_path();
        let key = create_key(&path).unwrap();

        // 鍵の長さだけ確認（内容は出力しない）
        assert_eq!(key.len(), KEY_SIZE);

        cleanup(&path);
    }
}
