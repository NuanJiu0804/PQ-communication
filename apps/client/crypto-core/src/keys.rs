//! 身份密钥与预密钥。
//!
//! 身份由三部分组成:Ed25519(经典签名)、X25519(经典 DH)、ML-DSA-65(后量子签名)。
//! 预密钥的公钥由身份密钥做「经典 + 后量子」混合签名,任一被攻破都不足以伪造。

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::classical;
use crate::error::{CryptoError, Result};
use crate::pqc;

/// 长期身份私钥集合(本地持有,绝不外发)。
#[derive(Serialize, Deserialize)]
pub struct IdentityKeyPair {
    /// Ed25519 私钥(经典签名)。
    pub ik_ed_secret: [u8; 32],
    /// X25519 私钥(经典 DH)。
    pub ik_x_secret: [u8; 32],
    /// ML-DSA-65 私钥种子(后量子签名)。
    pub ik_mldsa_secret: [u8; 32],
}

/// 身份公钥集合(对外发布)。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityPublic {
    /// Ed25519 公钥。
    pub ik_ed: [u8; 32],
    /// X25519 公钥。
    pub ik_x: [u8; 32],
    /// ML-DSA-65 验证公钥(1952 字节)。
    pub ik_mldsa: Vec<u8>,
}

impl IdentityKeyPair {
    /// 生成一套全新的身份密钥。
    pub fn generate() -> Self {
        Self {
            ik_ed_secret: classical::ed25519_generate().secret,
            ik_x_secret: classical::x25519_generate().secret,
            ik_mldsa_secret: pqc::dsa_generate().secret_seed,
        }
    }

    /// 导出对应的身份公钥。
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            ik_ed: classical::ed25519_public(&self.ik_ed_secret),
            ik_x: classical::x25519_public(&self.ik_x_secret),
            ik_mldsa: pqc::dsa_public(&self.ik_mldsa_secret),
        }
    }
}

/// 签名预密钥(X25519),其公钥由身份密钥混合签名。
#[derive(Serialize, Deserialize)]
pub struct SignedPreKey {
    /// 预密钥编号。
    pub id: u32,
    /// X25519 私钥。
    pub secret: [u8; 32],
    /// X25519 公钥。
    pub public: [u8; 32],
    /// Ed25519 对公钥的签名。
    #[serde(with = "BigArray")]
    pub sig_ed: [u8; 64],
    /// ML-DSA-65 对公钥的签名。
    pub sig_mldsa: Vec<u8>,
}

impl SignedPreKey {
    /// 生成签名预密钥。
    pub fn generate(identity: &IdentityKeyPair, id: u32) -> Self {
        let kp = classical::x25519_generate();
        let payload = prekey_payload(b"spk", &kp.public);
        Self {
            id,
            secret: kp.secret,
            public: kp.public,
            sig_ed: classical::ed25519_sign(&identity.ik_ed_secret, &payload),
            sig_mldsa: pqc::dsa_sign(&identity.ik_mldsa_secret, &payload),
        }
    }
}

/// 一次性预密钥(X25519)。
#[derive(Serialize, Deserialize)]
pub struct OneTimePreKey {
    /// 预密钥编号。
    pub id: u32,
    /// X25519 私钥。
    pub secret: [u8; 32],
    /// X25519 公钥。
    pub public: [u8; 32],
}

impl OneTimePreKey {
    /// 生成一次性预密钥。
    pub fn generate(id: u32) -> Self {
        let kp = classical::x25519_generate();
        Self {
            id,
            secret: kp.secret,
            public: kp.public,
        }
    }
}

/// 后量子预密钥(ML-KEM-768),其公钥由身份密钥混合签名。
#[derive(Serialize, Deserialize)]
pub struct PqPreKey {
    /// 预密钥编号。
    pub id: u32,
    /// ML-KEM-768 私钥种子。
    #[serde(with = "BigArray")]
    pub secret_seed: [u8; 64],
    /// ML-KEM-768 公钥(封装密钥,1184 字节)。
    pub public_ek: Vec<u8>,
    /// Ed25519 对公钥的签名。
    #[serde(with = "BigArray")]
    pub sig_ed: [u8; 64],
    /// ML-DSA-65 对公钥的签名。
    pub sig_mldsa: Vec<u8>,
}

impl PqPreKey {
    /// 生成后量子预密钥。
    pub fn generate(identity: &IdentityKeyPair, id: u32) -> Self {
        let kp = pqc::kem_generate();
        let payload = prekey_payload(b"pqkem", &kp.public_ek);
        Self {
            id,
            secret_seed: kp.secret_seed,
            sig_ed: classical::ed25519_sign(&identity.ik_ed_secret, &payload),
            sig_mldsa: pqc::dsa_sign(&identity.ik_mldsa_secret, &payload),
            public_ek: kp.public_ek,
        }
    }
}

/// 对外发布的预密钥包(发起方据此异步建立会话)。
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// 对方身份公钥。
    pub identity: IdentityPublic,
    /// 签名预密钥编号。
    pub spk_id: u32,
    /// 签名预密钥公钥。
    pub spk_public: [u8; 32],
    /// 签名预密钥的 Ed25519 签名。
    pub spk_sig_ed: [u8; 64],
    /// 签名预密钥的 ML-DSA 签名。
    pub spk_sig_mldsa: Vec<u8>,
    /// 一次性预密钥编号(可选)。
    pub opk_id: Option<u32>,
    /// 一次性预密钥公钥(可选)。
    pub opk_public: Option<[u8; 32]>,
    /// 后量子预密钥编号。
    pub pq_id: u32,
    /// 后量子预密钥公钥。
    pub pq_public_ek: Vec<u8>,
    /// 后量子预密钥的 Ed25519 签名。
    pub pq_sig_ed: [u8; 64],
    /// 后量子预密钥的 ML-DSA 签名。
    pub pq_sig_mldsa: Vec<u8>,
}

impl PreKeyBundle {
    /// 由本地密钥组装一个公开预密钥包。
    pub fn assemble(
        identity: IdentityPublic,
        spk: &SignedPreKey,
        opk: Option<&OneTimePreKey>,
        pq: &PqPreKey,
    ) -> Self {
        Self {
            identity,
            spk_id: spk.id,
            spk_public: spk.public,
            spk_sig_ed: spk.sig_ed,
            spk_sig_mldsa: spk.sig_mldsa.clone(),
            opk_id: opk.map(|o| o.id),
            opk_public: opk.map(|o| o.public),
            pq_id: pq.id,
            pq_public_ek: pq.public_ek.clone(),
            pq_sig_ed: pq.sig_ed,
            pq_sig_mldsa: pq.sig_mldsa.clone(),
        }
    }

    /// 校验预密钥包:签名预密钥与后量子预密钥都必须通过「经典 + 后量子」双重验签。
    pub fn verify(&self) -> Result<()> {
        let spk_payload = prekey_payload(b"spk", &self.spk_public);
        if !classical::ed25519_verify(&self.identity.ik_ed, &spk_payload, &self.spk_sig_ed)
            || !pqc::dsa_verify(&self.identity.ik_mldsa, &spk_payload, &self.spk_sig_mldsa)
        {
            return Err(CryptoError::InvalidPrekeyBundle);
        }

        let pq_payload = prekey_payload(b"pqkem", &self.pq_public_ek);
        if !classical::ed25519_verify(&self.identity.ik_ed, &pq_payload, &self.pq_sig_ed)
            || !pqc::dsa_verify(&self.identity.ik_mldsa, &pq_payload, &self.pq_sig_mldsa)
        {
            return Err(CryptoError::InvalidPrekeyBundle);
        }
        Ok(())
    }
}

/// 构造预密钥签名所覆盖的字节:域分隔标签 + 用途 + 公钥。
fn prekey_payload(label: &[u8], public: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + label.len() + public.len());
    v.extend_from_slice(b"PQChat-PreKeySig-v1:");
    v.extend_from_slice(label);
    v.push(b':');
    v.extend_from_slice(public);
    v
}
