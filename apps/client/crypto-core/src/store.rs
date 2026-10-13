//! 本地加密存储的密码学构件:Argon2id 口令派生密钥 + XChaCha20-Poly1305 封装。
//!
//! 这是 SQLCipher 的同级方案——加密完全用本 crate 的成熟原语完成,
//! 跨平台一致、无 OpenSSL 等原生依赖。上层(Tauri)负责把封装后的密文落盘。

use argon2::Argon2;

use crate::aead;
use crate::error::{CryptoError, Result};
use crate::random;

/// 盐长度。
pub const SALT_LEN: usize = 16;

const STORE_AAD: &[u8] = b"PQChat-LocalStore-v1";

/// 生成随机盐(非机密,可明文保存)。
pub fn generate_salt() -> [u8; SALT_LEN] {
    random::random_array::<SALT_LEN>()
}

/// 由口令与盐用 Argon2id 派生 32 字节存储密钥。
pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| CryptoError::InvalidState)?;
    Ok(key)
}

/// 用存储密钥加密明文,输出 nonce(24) ‖ 密文(随机 nonce,无复用风险)。
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let nonce = random::random_array::<24>();
    let ciphertext = aead::encrypt(key, &nonce, plaintext, STORE_AAD);
    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// 解密 seal 的输出。
pub fn open(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 24 {
        return Err(CryptoError::InvalidMessage);
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&data[..24]);
    aead::decrypt(key, &nonce, &data[24..], STORE_AAD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let salt = generate_salt();
        let key = derive_key(b"correct horse battery staple", &salt).unwrap();
        let sealed = seal(&key, b"serialized client manager state");
        assert_eq!(open(&key, &sealed).unwrap(), b"serialized client manager state");
    }

    #[test]
    fn wrong_password_cannot_open() {
        let salt = generate_salt();
        let k1 = derive_key(b"password-one", &salt).unwrap();
        let k2 = derive_key(b"password-two", &salt).unwrap();
        let sealed = seal(&k1, b"sensitive");
        assert!(open(&k2, &sealed).is_err());
    }

    #[test]
    fn tampered_blob_rejected() {
        let salt = generate_salt();
        let key = derive_key(b"pw", &salt).unwrap();
        let mut sealed = seal(&key, b"data");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(open(&key, &sealed).is_err());
    }
}
