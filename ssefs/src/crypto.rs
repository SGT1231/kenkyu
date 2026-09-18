use sha2::{
    Digest,
    Sha256,
};

use aes_gcm::{
    Aes256Gcm,
    KeyInit,
    Nonce,
    aead::Aead,
};

use base64::{
    engine::general_purpose::STANDARD,
    Engine,
};

use rand::RngCore;

use crate::key_manager;

pub fn make_token(
    secret: &str,
    query: &str,
) -> String {

    let mut hasher =
        Sha256::new();

    hasher.update(secret);
    hasher.update(query);

    hex::encode(
        hasher.finalize()
    )
}

pub fn encrypt(
    file: &str,
) -> String {
    encrypt_bytes(file.as_bytes())
}

pub fn encrypt_bytes(
    file: &[u8],
) -> String {

    let key = key_manager::get_key();
    let cipher =
        Aes256Gcm::new_from_slice(key)
            .unwrap();

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng()
        .fill_bytes(&mut nonce_bytes);

    let nonce =
        Nonce::from_slice(&nonce_bytes);

    let ciphertext =
        cipher.encrypt(
            nonce,
            file,
        )
        .unwrap();

    let mut result =
        nonce_bytes.to_vec();

    result.extend(ciphertext);

    STANDARD.encode(result)
}

pub fn decrypt(
    file: &str,
) -> String {

    let data = STANDARD.decode(file.trim()).unwrap();

    if data.is_empty() {
        return String::new();
    }

    let (nonce_bytes, ciphertext) =
        data.split_at(12);

    let key = key_manager::get_key();
    let cipher =
        Aes256Gcm::new_from_slice(key)
            .unwrap();

    let nonce =
        Nonce::from_slice(nonce_bytes);

    let plaintext =
        cipher.decrypt(
            nonce,
            ciphertext,
        )
        .unwrap();

    String::from_utf8(plaintext)
        .unwrap()
}

// --- Forward Privacy (Sophos-style TDP) ---

use hmac::{Hmac, Mac};
use num_bigint_dig::BigUint;

type HmacSha256 = Hmac<Sha256>;

/// master_key と keyword_id から dk (derivation key) を導出
pub fn derive_dk(master_key: &[u8], keyword_id: &str) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master_key)
        .expect("HMAC can take key of any size");
    mac.update(b"derive_dk");
    mac.update(keyword_id.as_bytes());
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut dk = [0u8; 32];
    dk.copy_from_slice(&bytes);
    dk
}

/// ST (Search Token) から UT (Update Token) を導出
pub fn derive_ut(dk: &[u8; 32], st: &BigUint) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(dk)
        .expect("HMAC can take key of any size");
    mac.update(&st.to_bytes_be());
    mac.update(b"derive_ut");
    let result = mac.finalize();
    let bytes = result.into_bytes();
    hex::encode(bytes)
}

/// keyword_id に対する初期 ST_0 を生成 (0 < st < n)
pub fn st_init(master_key: &[u8], keyword_id: &str, n: &BigUint) -> BigUint {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master_key)
        .expect("HMAC can take key of any size");
    mac.update(b"st_init");
    mac.update(keyword_id.as_bytes());
    let mut seed = mac.finalize().into_bytes().to_vec();

    loop {
        let candidate = BigUint::from_bytes_be(&seed);
        if candidate < *n && candidate != BigUint::from(0u32) {
            return candidate;
        }
        let mut mac2 = <HmacSha256 as Mac>::new_from_slice(master_key)
            .expect("HMAC can take key of any size");
        mac2.update(&seed);
        mac2.update(b"next");
        seed = mac2.finalize().into_bytes().to_vec();
    }
}

/// ST の進化: next_st = st^d mod n (TDP inverse / クライアント側)
pub fn st_next(st: &BigUint, d: &BigUint, n: &BigUint) -> BigUint {
    st.modpow(d, n)
}

/// BigUint を Base64 文字列にエンコード
pub fn biguint_to_base64(st: &BigUint) -> String {
    STANDARD.encode(st.to_bytes_be())
}

/// Base64 文字列を BigUint にデコード
pub fn base64_to_biguint(s: &str) -> Option<BigUint> {
    let bytes = STANDARD.decode(s).ok()?;
    Some(BigUint::from_bytes_be(&bytes))
}
