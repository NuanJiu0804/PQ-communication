//! 高层会话:把 PQXDH 握手与双棘轮组合成易用的 1:1 加密会话。

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::keys::{
    IdentityKeyPair, IdentityPublic, OneTimePreKey, PqPreKey, PreKeyBundle, SignedPreKey,
};
use crate::pqxdh::{self, InitialMessage};
use crate::ratchet::{RatchetMessage, RatchetState};

/// 一个端到端加密会话。
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    ratchet: RatchetState,
    associated_data: Vec<u8>,
}

impl Session {
    /// 发起方:据对方预密钥包建立会话,返回会话与需随首条消息发送的握手头。
    pub fn initiate(
        my_identity: &IdentityKeyPair,
        bundle: &PreKeyBundle,
    ) -> Result<(Self, InitialMessage)> {
        let (message, sk, their_ratchet_public) = pqxdh::initiate(my_identity, bundle)?;
        let ratchet = RatchetState::init_alice(sk, their_ratchet_public);
        let associated_data = make_ad(&my_identity.public(), &bundle.identity);
        Ok((
            Self {
                ratchet,
                associated_data,
            },
            message,
        ))
    }

    /// 响应方:收到握手头后建立会话。
    pub fn respond(
        my_identity: &IdentityKeyPair,
        spk: &SignedPreKey,
        opk: Option<&OneTimePreKey>,
        pq: &PqPreKey,
        message: &InitialMessage,
    ) -> Result<Self> {
        let sk = pqxdh::respond(my_identity, spk, opk, pq, message)?;
        let ratchet = RatchetState::init_bob(sk, spk.secret, spk.public);
        let associated_data = make_ad(&message.identity, &my_identity.public());
        Ok(Self {
            ratchet,
            associated_data,
        })
    }

    /// 加密一条明文消息(响应方在收到首条消息前无发送链,返回错误)。
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage> {
        self.ratchet.encrypt(plaintext, &self.associated_data)
    }

    /// 解密一条棘轮消息。
    pub fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>> {
        self.ratchet.decrypt(message, &self.associated_data)
    }
}

/// 会话附加认证数据:域分隔 ‖ 发起方身份 ‖ 响应方身份。
/// 双方对「谁是发起方」一致,因此各自算得相同的 AD,把会话绑定到双方身份。
fn make_ad(initiator: &IdentityPublic, responder: &IdentityPublic) -> Vec<u8> {
    let mut ad = Vec::new();
    ad.extend_from_slice(b"PQChat-SessionAD-v1");
    ad.extend_from_slice(&initiator.ik_ed);
    ad.extend_from_slice(&initiator.ik_x);
    ad.extend_from_slice(&initiator.ik_mldsa);
    ad.extend_from_slice(&responder.ik_ed);
    ad.extend_from_slice(&responder.ik_x);
    ad.extend_from_slice(&responder.ik_mldsa);
    ad
}
