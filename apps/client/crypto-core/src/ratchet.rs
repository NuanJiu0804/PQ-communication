//! 双棘轮(Double Ratchet):前向保密 + 后置入侵恢复。
//!
//! 实现遵循 Signal 双棘轮规范:X25519 DH 棘轮 + HMAC/HKDF 对称键链 +
//! XChaCha20-Poly1305 消息加密,支持乱序与跳号消息(保存跳过的消息密钥)。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::aead;
use crate::classical;
use crate::error::{CryptoError, Result};
use crate::kdf;

/// 单条会话允许跳过的最大消息数,防止恶意 N 触发资源耗尽。
const MAX_SKIP: u32 = 1000;
/// 跳过消息密钥缓存的总上限(跨多次 DH 棘轮累计),超出时淘汰旧条目。
const MAX_SKIPPED_TOTAL: usize = 2000;

/// 消息头:发送方当前棘轮公钥、上一发送链长度、本链内序号。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    /// 发送方棘轮公钥。
    pub dh: [u8; 32],
    /// 上一发送链的消息数(previous chain length)。
    pub pn: u32,
    /// 本链内消息序号。
    pub n: u32,
}

impl Header {
    /// 序列化为 40 字节,用作 AEAD 的附加认证数据。
    pub fn serialize(&self) -> [u8; 40] {
        let mut b = [0u8; 40];
        b[..32].copy_from_slice(&self.dh);
        b[32..36].copy_from_slice(&self.pn.to_be_bytes());
        b[36..40].copy_from_slice(&self.n.to_be_bytes());
        b
    }
}

/// 一条棘轮消息:头 + 密文。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// 消息头。
    pub header: Header,
    /// AEAD 密文(含认证标签)。
    pub ciphertext: Vec<u8>,
}

/// 双棘轮状态。
#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetState {
    dhs_secret: [u8; 32],
    dhs_public: [u8; 32],
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl RatchetState {
    /// 发起方初始化:已知对端初始棘轮公钥(对方签名预密钥公钥)。
    pub fn init_alice(sk: [u8; 32], their_dh_public: [u8; 32]) -> Self {
        let dhs = classical::x25519_generate();
        let (rk, cks) = kdf::kdf_rk(&sk, &classical::x25519_dh(&dhs.secret, &their_dh_public));
        Self {
            dhs_secret: dhs.secret,
            dhs_public: dhs.public,
            dhr: Some(their_dh_public),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    /// 响应方初始化:用自己的签名预密钥作为初始棘轮密钥对。
    pub fn init_bob(sk: [u8; 32], dh_secret: [u8; 32], dh_public: [u8; 32]) -> Self {
        Self {
            dhs_secret: dh_secret,
            dhs_public: dh_public,
            dhr: None,
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    /// 加密一条消息。响应方在收到对端首条消息之前没有发送链,此时返回错误。
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<RatchetMessage> {
        let cks = self.cks.ok_or(CryptoError::InvalidState)?;
        let (next_ck, mk) = kdf::kdf_ck(&cks);
        self.cks = Some(next_ck);

        let header = Header {
            dh: self.dhs_public,
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        let (key, nonce) = kdf::derive_message_keys(&mk);
        let aad = build_aad(associated_data, &header);
        let ciphertext = aead::encrypt(&key, &nonce, plaintext, &aad);

        Ok(RatchetMessage { header, ciphertext })
    }

    /// 解密一条消息(自动处理 DH 棘轮推进与乱序/跳号)。
    ///
    /// 事务语义:所有状态推进先在副本上进行,只有 AEAD 校验通过才提交。
    /// 否则攻击者伪造一条带新 DH 公钥的消息即可让接收方棘轮错位、会话永久失效
    /// (Signal 规范亦要求解密失败时丢弃状态变更)。
    pub fn decrypt(&mut self, message: &RatchetMessage, associated_data: &[u8]) -> Result<Vec<u8>> {
        let mut next = self.clone();
        let plaintext = next.decrypt_in_place(message, associated_data)?;
        *self = next;
        Ok(plaintext)
    }

    fn decrypt_in_place(&mut self, message: &RatchetMessage, associated_data: &[u8]) -> Result<Vec<u8>> {
        let key = (message.header.dh, message.header.n);
        if let Some(mk) = self.skipped.remove(&key) {
            return self.decrypt_with_mk(&mk, message, associated_data);
        }

        if self.dhr.as_ref() != Some(&message.header.dh) {
            self.skip_message_keys(message.header.pn)?;
            self.dh_ratchet(&message.header);
        }
        self.skip_message_keys(message.header.n)?;

        let ckr = self.ckr.ok_or(CryptoError::InvalidMessage)?;
        let (next_ck, mk) = kdf::kdf_ck(&ckr);
        self.ckr = Some(next_ck);
        self.nr += 1;

        self.decrypt_with_mk(&mk, message, associated_data)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if let Some(mut ckr) = self.ckr {
            if self.nr.saturating_add(MAX_SKIP) < until {
                return Err(CryptoError::InvalidMessage);
            }
            let dhr = self.dhr.ok_or(CryptoError::InvalidState)?;
            while self.nr < until {
                let (next_ck, mk) = kdf::kdf_ck(&ckr);
                if self.skipped.len() >= MAX_SKIPPED_TOTAL
                    && let Some(old) = self.skipped.keys().next().copied()
                {
                    self.skipped.remove(&old);
                }
                self.skipped.insert((dhr, self.nr), mk);
                ckr = next_ck;
                self.nr += 1;
            }
            self.ckr = Some(ckr);
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh);

        let (rk1, ckr) = kdf::kdf_rk(
            &self.rk,
            &classical::x25519_dh(&self.dhs_secret, &header.dh),
        );
        self.rk = rk1;
        self.ckr = Some(ckr);

        let new_dhs = classical::x25519_generate();
        self.dhs_secret = new_dhs.secret;
        self.dhs_public = new_dhs.public;

        let (rk2, cks) = kdf::kdf_rk(
            &self.rk,
            &classical::x25519_dh(&self.dhs_secret, &header.dh),
        );
        self.rk = rk2;
        self.cks = Some(cks);
    }

    fn decrypt_with_mk(
        &self,
        mk: &[u8; 32],
        message: &RatchetMessage,
        ad: &[u8],
    ) -> Result<Vec<u8>> {
        let (key, nonce) = kdf::derive_message_keys(mk);
        let aad = build_aad(ad, &message.header);
        aead::decrypt(&key, &nonce, &message.ciphertext, &aad)
    }
}

/// 组装 AEAD 附加认证数据:会话 AD ‖ 序列化消息头。
fn build_aad(associated_data: &[u8], header: &Header) -> Vec<u8> {
    let mut aad = Vec::with_capacity(associated_data.len() + 40);
    aad.extend_from_slice(associated_data);
    aad.extend_from_slice(&header.serialize());
    aad
}
