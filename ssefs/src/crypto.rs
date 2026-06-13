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

pub fn encrypt_filename(
    key: &[u8; 32],
    filename: &str,
) -> String {

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
            filename.as_bytes(),
        )
        .unwrap();

    let mut result =
        nonce_bytes.to_vec();

    result.extend(ciphertext);

    STANDARD.encode(result)
}

pub fn decrypt_filename(
    key: &[u8; 32],
    encoded: &str,
) -> String {

    let data =
        STANDARD.decode(encoded)
            .unwrap();

    let (nonce_bytes, ciphertext) =
        data.split_at(12);

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