//! AEAD 消息加密:XChaCha20-Poly1305(192-bit 随机/派生 nonce,无 nonce 复用风险)。

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::error::{CryptoError, Result};

/// AEAD 密钥长度。
pub const KEY_LEN: usize = 32;
/// XChaCha20 nonce 长度。
pub const NONCE_LEN: usize = 24;

/// 用 XChaCha20-Poly1305 加密,带附加认证数据(AAD)。
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 加密不应失败")
}

/// 用 XChaCha20-Poly1305 解密并校验 AAD;失败返回错误。
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_aad() {
        let key = [7u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"secret message", b"header");
        assert_eq!(
            decrypt(&key, &nonce, &ct, b"header").unwrap(),
            b"secret message"
        );
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [7u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"secret", b"header");
        assert!(decrypt(&key, &nonce, &ct, b"tampered").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [7u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let mut ct = encrypt(&key, &nonce, b"secret", b"");
        ct[0] ^= 0xFF;
        assert!(decrypt(&key, &nonce, &ct, b"").is_err());
    }
}
