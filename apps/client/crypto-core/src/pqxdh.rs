//! 混合 PQXDH 握手:经典 X25519 多次 DH ‖ 后量子 ML-KEM-768 封装,经 HKDF 得到会话根密钥。
//!
//! 支持对方离线时异步建立会话(发起方只需对方预先发布的预密钥包)。
//! 共享密钥的输入材料 = F ‖ DH1 ‖ DH2 ‖ DH3 ‖ (DH4) ‖ ss_pq,任一组件安全则整体安全。

use serde::{Deserialize, Serialize};

use crate::classical;
use crate::error::{CryptoError, Result};
use crate::kdf;
use crate::keys::{
    IdentityKeyPair, IdentityPublic, OneTimePreKey, PqPreKey, PreKeyBundle, SignedPreKey,
};
use crate::pqc;

/// 发起方随第一条消息一并发送的握手头。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialMessage {
    /// 发起方身份公钥。
    pub identity: IdentityPublic,
    /// 发起方临时公钥 EK。
    pub ephemeral_public: [u8; 32],
    /// 所用签名预密钥编号。
    pub used_spk_id: u32,
    /// 所用一次性预密钥编号(若有)。
    pub used_opk_id: Option<u32>,
    /// 所用后量子预密钥编号。
    pub used_pq_id: u32,
    /// ML-KEM 密文。
    pub kem_ciphertext: Vec<u8>,
}

/// 域分隔常量 F(32 字节 0xFF),置于密钥材料最前。
const F_PREFIX: [u8; 32] = [0xFF; 32];

/// 发起方:校验对方预密钥包并计算会话根密钥。
///
/// 返回 (初始握手头, 会话根密钥 SK, 对方签名预密钥公钥)。
/// 其中对方签名预密钥公钥用作双棘轮的初始对端棘轮公钥。
pub fn initiate(
    my_identity: &IdentityKeyPair,
    bundle: &PreKeyBundle,
) -> Result<(InitialMessage, [u8; 32], [u8; 32])> {
    bundle.verify()?;

    let ek = classical::x25519_generate();

    let dh1 = classical::x25519_dh(&my_identity.ik_x_secret, &bundle.spk_public);
    let dh2 = classical::x25519_dh(&ek.secret, &bundle.identity.ik_x);
    let dh3 = classical::x25519_dh(&ek.secret, &bundle.spk_public);

    let mut ikm = Vec::new();
    ikm.extend_from_slice(&F_PREFIX);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    if let Some(opk_public) = bundle.opk_public {
        let dh4 = classical::x25519_dh(&ek.secret, &opk_public);
        ikm.extend_from_slice(&dh4);
    }

    let (kem_ciphertext, ss_pq) = pqc::kem_encapsulate(&bundle.pq_public_ek)?;
    ikm.extend_from_slice(&ss_pq);

    let sk = kdf::derive_pqxdh_root(&ikm);

    let message = InitialMessage {
        identity: my_identity.public(),
        ephemeral_public: ek.public,
        used_spk_id: bundle.spk_id,
        used_opk_id: bundle.opk_id,
        used_pq_id: bundle.pq_id,
        kem_ciphertext,
    };

    Ok((message, sk, bundle.spk_public))
}

/// 响应方:用本地私钥重建会话根密钥。
///
/// `opk` 必须与发起方实际使用的一次性预密钥一致(由 `message.used_opk_id` 指示);
/// 若发起方未使用一次性预密钥,则传入 `None`。
pub fn respond(
    my_identity: &IdentityKeyPair,
    spk: &SignedPreKey,
    opk: Option<&OneTimePreKey>,
    pq: &PqPreKey,
    message: &InitialMessage,
) -> Result<[u8; 32]> {
    // 握手声明使用的预密钥必须与本地持有的一致,否则直接拒绝(而不是算出错误的根密钥)。
    if message.used_spk_id != spk.id
        || message.used_pq_id != pq.id
        || message.used_opk_id != opk.map(|o| o.id)
    {
        return Err(CryptoError::UnknownPreKey);
    }

    let dh1 = classical::x25519_dh(&spk.secret, &message.identity.ik_x);
    let dh2 = classical::x25519_dh(&my_identity.ik_x_secret, &message.ephemeral_public);
    let dh3 = classical::x25519_dh(&spk.secret, &message.ephemeral_public);

    let mut ikm = Vec::new();
    ikm.extend_from_slice(&F_PREFIX);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    if let Some(opk) = opk {
        let dh4 = classical::x25519_dh(&opk.secret, &message.ephemeral_public);
        ikm.extend_from_slice(&dh4);
    }

    let ss_pq = pqc::kem_decapsulate(&pq.secret_seed, &message.kem_ciphertext)?;
    ikm.extend_from_slice(&ss_pq);

    Ok(kdf::derive_pqxdh_root(&ikm))
}
