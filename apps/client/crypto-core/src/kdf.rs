//! 密钥派生函数:HKDF-SHA256 与 HMAC-SHA256,服务于 PQXDH 与双棘轮。
//!
//! 说明:本 crate 中形如 `PQChat-...-v1` 的字节串是**协议域分隔常量**(沿用早期项目代号),
//! 而非展示用的系统名称。它们参与密钥派生/签名/本地存储加密,一旦修改,已建立的会话、
//! 已发布的预密钥签名和已有的本地加密数据都将无法验证或解密,因此保持不变。

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// PQXDH 根密钥派生:对拼接好的密钥材料做 HKDF,得到 32 字节会话根密钥。
pub fn derive_pqxdh_root(ikm: &[u8]) -> [u8; 32] {
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"PQChat-PQXDH-v1", &mut okm)
        .expect("HKDF expand 长度有效");
    okm
}

/// 根 KDF(双棘轮 DH 棘轮步):由旧根密钥与 DH 输出派生 (新根密钥, 链密钥)。
pub fn kdf_rk(root_key: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(b"PQChat-Ratchet-RK-v1", &mut okm)
        .expect("HKDF expand 长度有效");
    let mut new_root = [0u8; 32];
    let mut chain = [0u8; 32];
    new_root.copy_from_slice(&okm[..32]);
    chain.copy_from_slice(&okm[32..]);
    (new_root, chain)
}

/// 链 KDF(对称键棘轮步):由链密钥派生 (新链密钥, 消息密钥)。
pub fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let message_key = hmac_sha256(chain_key, &[0x01]);
    let next_chain = hmac_sha256(chain_key, &[0x02]);
    (next_chain, message_key)
}

/// 由消息密钥派生 AEAD 的 (密钥, nonce)。
pub fn derive_message_keys(message_key: &[u8; 32]) -> ([u8; 32], [u8; 24]) {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), message_key);
    let mut okm = [0u8; 56];
    hk.expand(b"PQChat-Ratchet-MK-v1", &mut okm)
        .expect("HKDF expand 长度有效");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    (key, nonce)
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out[..32]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ck_advances_and_differs() {
        let ck = [1u8; 32];
        let (ck2, mk1) = kdf_ck(&ck);
        let (_ck3, mk2) = kdf_ck(&ck2);
        assert_ne!(ck, ck2);
        assert_ne!(mk1, mk2);
    }

    #[test]
    fn rk_is_deterministic() {
        let rk = [2u8; 32];
        let dh = [3u8; 32];
        assert_eq!(kdf_rk(&rk, &dh), kdf_rk(&rk, &dh));
    }

    #[test]
    fn message_keys_split() {
        let (k, n) = derive_message_keys(&[5u8; 32]);
        assert_eq!(k.len(), 32);
        assert_eq!(n.len(), 24);
    }
}
