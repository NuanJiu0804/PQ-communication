//! 经典原语薄封装:X25519(DH)与 Ed25519(签名)。

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::random;

/// X25519 公私钥字节长度。
pub const X25519_KEY_LEN: usize = 32;
/// Ed25519 公钥字节长度。
pub const ED25519_PUB_LEN: usize = 32;
/// Ed25519 签名字节长度。
pub const ED25519_SIG_LEN: usize = 64;

/// X25519 密钥对。
pub struct X25519Keypair {
    /// 私钥字节。
    pub secret: [u8; X25519_KEY_LEN],
    /// 公钥字节。
    pub public: [u8; X25519_KEY_LEN],
}

/// 生成 X25519 密钥对。
pub fn x25519_generate() -> X25519Keypair {
    let secret = random::random_array::<X25519_KEY_LEN>();
    let public = x25519_public(&secret);
    X25519Keypair { secret, public }
}

/// 由 X25519 私钥推导公钥。
pub fn x25519_public(secret: &[u8; X25519_KEY_LEN]) -> [u8; X25519_KEY_LEN] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// 计算 X25519 Diffie-Hellman 共享值。
pub fn x25519_dh(
    secret: &[u8; X25519_KEY_LEN],
    their_public: &[u8; X25519_KEY_LEN],
) -> [u8; X25519_KEY_LEN] {
    let sk = StaticSecret::from(*secret);
    let pk = PublicKey::from(*their_public);
    sk.diffie_hellman(&pk).to_bytes()
}

/// Ed25519 密钥对。
pub struct Ed25519Keypair {
    /// 私钥(种子)字节。
    pub secret: [u8; 32],
    /// 公钥字节。
    pub public: [u8; ED25519_PUB_LEN],
}

/// 生成 Ed25519 密钥对。
pub fn ed25519_generate() -> Ed25519Keypair {
    let secret = random::random_array::<32>();
    Ed25519Keypair {
        public: ed25519_public(&secret),
        secret,
    }
}

/// 由 Ed25519 私钥推导公钥。
pub fn ed25519_public(secret: &[u8; 32]) -> [u8; ED25519_PUB_LEN] {
    SigningKey::from_bytes(secret).verifying_key().to_bytes()
}

/// 用 Ed25519 私钥对消息签名。
pub fn ed25519_sign(secret: &[u8; 32], msg: &[u8]) -> [u8; ED25519_SIG_LEN] {
    SigningKey::from_bytes(secret).sign(msg).to_bytes()
}

/// 用 Ed25519 公钥校验签名。
pub fn ed25519_verify(
    public: &[u8; ED25519_PUB_LEN],
    msg: &[u8],
    sig: &[u8; ED25519_SIG_LEN],
) -> bool {
    let vk = match VerifyingKey::from_bytes(public) {
        Ok(v) => v,
        Err(_) => return false,
    };
    vk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_agreement() {
        let a = x25519_generate();
        let b = x25519_generate();
        assert_eq!(
            x25519_dh(&a.secret, &b.public),
            x25519_dh(&b.secret, &a.public)
        );
    }

    #[test]
    fn ed25519_sign_verify() {
        let kp = ed25519_generate();
        let sig = ed25519_sign(&kp.secret, b"hello");
        assert!(ed25519_verify(&kp.public, b"hello", &sig));
        assert!(!ed25519_verify(&kp.public, b"world", &sig));
    }
}
