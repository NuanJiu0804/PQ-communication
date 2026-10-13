//! 客户端会话管理器:持有本机身份/预密钥与全部会话,
//! 向上层(Tauri 命令)暴露字节级的加解密接口。私钥与会话状态都留在此处,不外泄。
//!
//! 健壮性设计(参照 Signal 的会话管理):
//! - 每个对端保留若干会话(首个为当前会话,其余为归档),解密时依次尝试,成功即提升为当前。
//!   这样双方同时发起会话、或对端重装后重新握手,都能自动收敛,而不会互相「踩掉」会话。
//! - 发起方在收到对端任何回复之前,每条消息都附带握手头(prekey 信封),首条丢失也能建立会话。
//! - 处理握手是事务性的:只有首条消息解密成功,才消费一次性预密钥、替换会话。
//! - 记录已处理握手的临时公钥,拒绝重放的握手消息(无一次性预密钥时尤其必要)。

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};
use crate::keys::{
    IdentityKeyPair, IdentityPublic, OneTimePreKey, PqPreKey, PreKeyBundle, SignedPreKey,
};
use crate::pqxdh::InitialMessage;
use crate::ratchet::RatchetMessage;
use crate::session::Session;
use crate::wire;

/// 持久化格式标记(v2)。旧版本(无标记)的数据在加载时自动迁移。
const FORMAT_MAGIC: &[u8; 4] = b"PQM2";
/// 每个对端最多保留的会话数(当前 + 归档)。
const MAX_SESSIONS_PER_PEER: usize = 5;
/// 本地最多保留的一次性预密钥私钥数量(超出时丢弃最旧的)。
const MAX_LOCAL_ONE_TIME_PREKEYS: usize = 200;

/// 信封类型:首条握手(prekey)或常规消息(message)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeType {
    /// 携带 PQXDH 握手头的消息(对端确认会话之前的所有消息)。
    Prekey,
    /// 会话建立后的常规棘轮消息。
    Message,
}

impl EnvelopeType {
    /// 线上字符串表示。
    pub fn label(self) -> &'static str {
        match self {
            EnvelopeType::Prekey => "prekey",
            EnvelopeType::Message => "message",
        }
    }

    /// 由字符串解析。
    pub fn from_label(s: &str) -> Result<Self> {
        match s {
            "prekey" => Ok(EnvelopeType::Prekey),
            "message" => Ok(EnvelopeType::Message),
            _ => Err(CryptoError::InvalidMessage),
        }
    }
}

/// 解密结果。
#[derive(Debug)]
pub struct Decrypted {
    /// 明文。
    pub plaintext: Vec<u8>,
    /// 对端身份公钥是否与此前记录的不同(安全号码已变化,需提醒用户重新核对)。
    pub identity_changed: bool,
}

/// 与某对端的一个会话及其握手元数据。
#[derive(Clone, Serialize, Deserialize)]
struct SessionEntry {
    session: Session,
    /// 本方发起且对端尚未回复时的握手头;确认前每条消息都附带它。
    pending: Option<InitialMessage>,
    /// 由对端握手建立的会话:记录对端临时公钥,用于识别同一握手的后续 prekey 消息。
    origin: Option<[u8; 32]>,
}

/// 客户端会话管理器。
#[derive(Serialize, Deserialize)]
pub struct ClientManager {
    identity: IdentityKeyPair,
    signed_prekey: SignedPreKey,
    pq_prekey: PqPreKey,
    one_time_prekeys: Vec<OneTimePreKey>,
    next_one_time_id: u32,
    /// 每个对端的会话列表,下标 0 为当前会话。
    sessions: HashMap<String, Vec<SessionEntry>>,
    peers: HashMap<String, IdentityPublic>,
    seen_handshakes: HashSet<[u8; 32]>,
}

/// 旧版(v1)持久化结构,仅用于迁移已有的本地数据。字段顺序须与旧版完全一致。
#[derive(Serialize, Deserialize)]
struct LegacyClientManager {
    identity: IdentityKeyPair,
    signed_prekey: SignedPreKey,
    pq_prekey: PqPreKey,
    one_time_prekeys: Vec<OneTimePreKey>,
    sessions: HashMap<String, Session>,
    peers: HashMap<String, IdentityPublic>,
    pending: HashMap<String, InitialMessage>,
}

impl From<LegacyClientManager> for ClientManager {
    fn from(mut old: LegacyClientManager) -> Self {
        let max_id = old.one_time_prekeys.iter().map(|o| o.id).max().unwrap_or(0);
        let sessions = old
            .sessions
            .into_iter()
            .map(|(peer, session)| {
                let pending = old.pending.remove(&peer);
                (peer, vec![SessionEntry { session, pending, origin: None }])
            })
            .collect();
        Self {
            identity: old.identity,
            signed_prekey: old.signed_prekey,
            pq_prekey: old.pq_prekey,
            one_time_prekeys: old.one_time_prekeys,
            // 旧版不记录已发放的编号,跳过一段区间以免与服务器上残留的编号冲突
            next_one_time_id: max_id.max(100) + 1,
            sessions,
            peers: old.peers,
            seen_handshakes: HashSet::new(),
        }
    }
}

impl ClientManager {
    /// 新建管理器:生成身份、签名预密钥、后量子预密钥与若干一次性预密钥。
    pub fn new(one_time_count: u32) -> Self {
        let identity = IdentityKeyPair::generate();
        let signed_prekey = SignedPreKey::generate(&identity, 1);
        let pq_prekey = PqPreKey::generate(&identity, 1);
        let one_time_prekeys = (1..=one_time_count).map(OneTimePreKey::generate).collect();
        Self {
            identity,
            signed_prekey,
            pq_prekey,
            one_time_prekeys,
            next_one_time_id: one_time_count + 1,
            sessions: HashMap::new(),
            peers: HashMap::new(),
            seen_handshakes: HashSet::new(),
        }
    }

    /// 本机身份公钥。
    pub fn identity_public(&self) -> IdentityPublic {
        self.identity.public()
    }

    /// 当前签名预密钥。
    pub fn signed_prekey(&self) -> &SignedPreKey {
        &self.signed_prekey
    }

    /// 当前后量子预密钥。
    pub fn pq_prekey(&self) -> &PqPreKey {
        &self.pq_prekey
    }

    /// 当前一次性预密钥集合。
    pub fn one_time_prekeys(&self) -> &[OneTimePreKey] {
        &self.one_time_prekeys
    }

    /// 补充生成 `count` 个一次性预密钥(编号单调递增、不复用),返回新生成的那部分。
    pub fn generate_one_time_prekeys(&mut self, count: u32) -> &[OneTimePreKey] {
        for _ in 0..count {
            let id = self.next_one_time_id;
            self.next_one_time_id = self.next_one_time_id.wrapping_add(1).max(1);
            self.one_time_prekeys.push(OneTimePreKey::generate(id));
        }
        if self.one_time_prekeys.len() > MAX_LOCAL_ONE_TIME_PREKEYS {
            let excess = self.one_time_prekeys.len() - MAX_LOCAL_ONE_TIME_PREKEYS;
            self.one_time_prekeys.drain(..excess);
        }
        let start = self.one_time_prekeys.len() - (count as usize).min(self.one_time_prekeys.len());
        &self.one_time_prekeys[start..]
    }

    /// 是否已与某对端建立会话。
    pub fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.get(peer_id).is_some_and(|v| !v.is_empty())
    }

    /// 发起方:据对方预密钥包建立新会话(之后的消息以 prekey 信封发出,直到对端回复)。
    /// 返回对端身份是否与此前记录的不同。
    pub fn start_session(&mut self, peer_id: &str, bundle: &PreKeyBundle) -> Result<bool> {
        let (session, initial) = Session::initiate(&self.identity, bundle)?;
        let changed = self.record_peer_identity(peer_id, &bundle.identity);
        self.push_session(
            peer_id,
            SessionEntry { session, pending: Some(initial), origin: None },
        );
        Ok(changed)
    }

    /// 加密一条消息,返回 (信封类型, 负载字节)。
    pub fn encrypt(&mut self, peer_id: &str, plaintext: &[u8]) -> Result<(EnvelopeType, Vec<u8>)> {
        let entry = self
            .sessions
            .get_mut(peer_id)
            .and_then(|v| v.first_mut())
            .ok_or(CryptoError::NoSession)?;
        let message = entry.session.encrypt(plaintext)?;
        match &entry.pending {
            Some(initial) => Ok((
                EnvelopeType::Prekey,
                wire::encode_prekey_payload(initial, &message),
            )),
            None => Ok((EnvelopeType::Message, wire::encode_message(&message))),
        }
    }

    /// 解密一条消息;若是对端的新握手,则作为响应方建立会话。
    pub fn decrypt(&mut self, peer_id: &str, env_type: EnvelopeType, payload: &[u8]) -> Result<Decrypted> {
        match env_type {
            EnvelopeType::Message => {
                let message = wire::decode_message(payload)?;
                if !self.has_session(peer_id) {
                    return Err(CryptoError::NoSession);
                }
                let plaintext = self.decrypt_existing(peer_id, &message, |_| true)?;
                Ok(Decrypted { plaintext, identity_changed: false })
            }
            EnvelopeType::Prekey => {
                let (initial, message) = wire::decode_prekey_payload(payload)?;
                let eph = initial.ephemeral_public;

                // 同一握手的后续消息(对端尚未收到我们的回复,仍在附带握手头)
                let known = self
                    .sessions
                    .get(peer_id)
                    .is_some_and(|v| v.iter().any(|e| e.origin == Some(eph)));
                if known {
                    let plaintext =
                        self.decrypt_existing(peer_id, &message, |e| e.origin == Some(eph))?;
                    return Ok(Decrypted { plaintext, identity_changed: false });
                }
                if self.seen_handshakes.contains(&eph) {
                    return Err(CryptoError::ReplayedHandshake);
                }
                // 兼容旧版本:旧版建立的响应方会话没有记录 origin
                if let Ok(plaintext) = self.decrypt_existing(peer_id, &message, |e| {
                    e.origin.is_none() && e.pending.is_none()
                }) {
                    if let Some(entry) = self.sessions.get_mut(peer_id).and_then(|v| v.first_mut()) {
                        entry.origin = Some(eph);
                    }
                    self.seen_handshakes.insert(eph);
                    return Ok(Decrypted { plaintext, identity_changed: false });
                }
                self.respond(peer_id, &initial, &message)
            }
        }
    }

    /// 与某对端的安全号码(需已知对端身份,即已建立会话或已收到其首条消息)。
    pub fn safety_number(&self, peer_id: &str) -> Result<String> {
        let peer = self.peers.get(peer_id).ok_or(CryptoError::NoSession)?;
        Ok(crate::fingerprint::safety_number(&self.identity.public(), peer))
    }

    /// 序列化整个管理器状态(身份/预密钥/会话),用于本地加密落盘。
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let body = bincode::serialize(self).map_err(|_| CryptoError::InvalidState)?;
        let mut out = Vec::with_capacity(FORMAT_MAGIC.len() + body.len());
        out.extend_from_slice(FORMAT_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// 从字节恢复管理器状态(兼容旧版格式)。
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        match data.strip_prefix(FORMAT_MAGIC) {
            Some(body) => bincode::deserialize(body).map_err(|_| CryptoError::InvalidState),
            None => bincode::deserialize::<LegacyClientManager>(data)
                .map(Self::from)
                .map_err(|_| CryptoError::InvalidState),
        }
    }

    // ---- 内部 ----

    /// 依次用满足 `filter` 的会话尝试解密;成功则提升为当前会话并视为对端已确认。
    fn decrypt_existing(
        &mut self,
        peer_id: &str,
        message: &RatchetMessage,
        filter: impl Fn(&SessionEntry) -> bool,
    ) -> Result<Vec<u8>> {
        let entries = self.sessions.get_mut(peer_id).ok_or(CryptoError::NoSession)?;
        let mut last_err = CryptoError::DecryptionFailed;
        for i in 0..entries.len() {
            if !filter(&entries[i]) {
                continue;
            }
            // Session::decrypt 失败时不改变状态,可放心逐个尝试
            match entries[i].session.decrypt(message) {
                Ok(plaintext) => {
                    let mut entry = entries.remove(i);
                    entry.pending = None;
                    entries.insert(0, entry);
                    return Ok(plaintext);
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    /// 作为响应方处理一次新握手:先在临时状态上完成握手与首条解密,成功后才提交。
    fn respond(
        &mut self,
        peer_id: &str,
        initial: &InitialMessage,
        message: &RatchetMessage,
    ) -> Result<Decrypted> {
        let opk_pos = match initial.used_opk_id {
            Some(id) => Some(
                self.one_time_prekeys
                    .iter()
                    .position(|o| o.id == id)
                    .ok_or(CryptoError::UnknownPreKey)?,
            ),
            None => None,
        };
        let opk = opk_pos.map(|pos| &self.one_time_prekeys[pos]);
        let mut session = Session::respond(
            &self.identity,
            &self.signed_prekey,
            opk,
            &self.pq_prekey,
            initial,
        )?;
        let plaintext = session.decrypt(message)?;

        // ---- 提交 ----
        if let Some(pos) = opk_pos {
            self.one_time_prekeys.remove(pos);
        }
        self.seen_handshakes.insert(initial.ephemeral_public);
        let identity_changed = self.record_peer_identity(peer_id, &initial.identity);
        self.push_session(
            peer_id,
            SessionEntry {
                session,
                pending: None,
                origin: Some(initial.ephemeral_public),
            },
        );
        Ok(Decrypted { plaintext, identity_changed })
    }

    /// 记录对端身份;返回是否与此前记录的不同。
    fn record_peer_identity(&mut self, peer_id: &str, identity: &IdentityPublic) -> bool {
        let changed = self.peers.get(peer_id).is_some_and(|old| old != identity);
        self.peers.insert(peer_id.to_string(), identity.clone());
        changed
    }

    /// 把新会话设为当前会话,旧会话归档(超出上限的最旧会话被丢弃)。
    fn push_session(&mut self, peer_id: &str, entry: SessionEntry) {
        let entries = self.sessions.entry(peer_id.to_string()).or_default();
        entries.insert(0, entry);
        entries.truncate(MAX_SESSIONS_PER_PEER);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::PreKeyBundle;

    /// 模拟服务器分发:取其首个一次性预密钥(并像服务器一样「消费」掉它)。
    struct Directory {
        handed_out: HashSet<u32>,
    }

    impl Directory {
        fn new() -> Self {
            Self { handed_out: HashSet::new() }
        }

        fn bundle(&mut self, m: &ClientManager) -> PreKeyBundle {
            let opk = m
                .one_time_prekeys()
                .iter()
                .find(|o| !self.handed_out.contains(&o.id));
            if let Some(o) = opk {
                self.handed_out.insert(o.id);
            }
            PreKeyBundle::assemble(m.identity_public(), m.signed_prekey(), opk, m.pq_prekey())
        }
    }

    fn published_bundle(m: &ClientManager) -> PreKeyBundle {
        Directory::new().bundle(m)
    }

    fn dec(m: &mut ClientManager, peer: &str, (t, p): &(EnvelopeType, Vec<u8>)) -> Result<Vec<u8>> {
        m.decrypt(peer, *t, p).map(|d| d.plaintext)
    }

    #[test]
    fn manager_end_to_end() {
        let mut alice = ClientManager::new(5);
        let mut bob = ClientManager::new(5);
        let bundle = published_bundle(&bob);

        assert!(!alice.start_session("bob", &bundle).unwrap());

        // 首条:prekey 信封
        let m1 = alice.encrypt("bob", "你好 Bob".as_bytes()).unwrap();
        assert_eq!(m1.0, EnvelopeType::Prekey);
        assert_eq!(dec(&mut bob, "alice", &m1).unwrap(), "你好 Bob".as_bytes());

        // 回复:普通消息
        let m2 = bob.encrypt("alice", b"hi alice").unwrap();
        assert_eq!(m2.0, EnvelopeType::Message);
        assert_eq!(dec(&mut alice, "bob", &m2).unwrap(), b"hi alice");

        // Alice 收到回复后改发普通消息
        let m3 = alice.encrypt("bob", b"round two").unwrap();
        assert_eq!(m3.0, EnvelopeType::Message);
        assert_eq!(dec(&mut bob, "alice", &m3).unwrap(), b"round two");

        // 安全号码双方一致
        assert_eq!(
            alice.safety_number("bob").unwrap(),
            bob.safety_number("alice").unwrap()
        );
    }

    #[test]
    fn prekey_header_repeated_until_reply() {
        // 回归:对端回复前每条消息都带握手头;即使首条丢失,后续消息也能建立会话。
        let mut alice = ClientManager::new(5);
        let mut bob = ClientManager::new(5);
        alice.start_session("bob", &published_bundle(&bob)).unwrap();

        let _lost = alice.encrypt("bob", b"lost").unwrap();
        let m2 = alice.encrypt("bob", b"second").unwrap();
        let m3 = alice.encrypt("bob", b"third").unwrap();
        assert_eq!(m2.0, EnvelopeType::Prekey);
        assert_eq!(m3.0, EnvelopeType::Prekey);

        assert_eq!(dec(&mut bob, "alice", &m2).unwrap(), b"second");
        // 同一握手的后续 prekey 消息复用已建立的会话,而不是被当作重放拒绝
        assert_eq!(dec(&mut bob, "alice", &m3).unwrap(), b"third");

        let r = bob.encrypt("alice", b"reply").unwrap();
        assert_eq!(dec(&mut alice, "bob", &r).unwrap(), b"reply");
        assert_eq!(alice.encrypt("bob", b"x").unwrap().0, EnvelopeType::Message);
    }

    #[test]
    fn manager_simultaneous_initiation() {
        // 回归:双方几乎同时发起会话并各自发出首条消息,最终仍能双向通信。
        let mut alice = ClientManager::new(5);
        let mut bob = ClientManager::new(5);
        let alice_bundle = published_bundle(&alice);
        let bob_bundle = published_bundle(&bob);

        alice.start_session("bob", &bob_bundle).unwrap();
        bob.start_session("alice", &alice_bundle).unwrap();

        let a1 = alice.encrypt("bob", "你好 Bob".as_bytes()).unwrap();
        let b1 = bob.encrypt("alice", "你好 Alice".as_bytes()).unwrap();
        assert_eq!(a1.0, EnvelopeType::Prekey);
        assert_eq!(b1.0, EnvelopeType::Prekey);

        // 两条握手交叉到达
        assert_eq!(dec(&mut bob, "alice", &a1).unwrap(), "你好 Bob".as_bytes());
        assert_eq!(dec(&mut alice, "bob", &b1).unwrap(), "你好 Alice".as_bytes());

        // 之后多轮往返都能解密(归档会话被自动提升)
        for round in 0..3 {
            let a = alice.encrypt("bob", format!("a{round}").as_bytes()).unwrap();
            assert_eq!(dec(&mut bob, "alice", &a).unwrap(), format!("a{round}").as_bytes());
            let b = bob.encrypt("alice", format!("b{round}").as_bytes()).unwrap();
            assert_eq!(dec(&mut alice, "bob", &b).unwrap(), format!("b{round}").as_bytes());
        }

        assert_eq!(
            alice.safety_number("bob").unwrap(),
            bob.safety_number("alice").unwrap()
        );
    }

    #[test]
    fn simultaneous_initiation_one_side_first() {
        // 双方都建立了会话,但只有 Alice 先发;Bob 随后回复。
        let mut alice = ClientManager::new(5);
        let mut bob = ClientManager::new(5);
        let alice_bundle = published_bundle(&alice);
        let bob_bundle = published_bundle(&bob);
        alice.start_session("bob", &bob_bundle).unwrap();
        bob.start_session("alice", &alice_bundle).unwrap();

        let a1 = alice.encrypt("bob", b"first").unwrap();
        assert_eq!(dec(&mut bob, "alice", &a1).unwrap(), b"first");
        let b1 = bob.encrypt("alice", b"reply").unwrap();
        assert_eq!(b1.0, EnvelopeType::Message);
        assert_eq!(dec(&mut alice, "bob", &b1).unwrap(), b"reply");
        let a2 = alice.encrypt("bob", b"again").unwrap();
        assert_eq!(a2.0, EnvelopeType::Message);
        assert_eq!(dec(&mut bob, "alice", &a2).unwrap(), b"again");
    }

    #[test]
    fn replayed_handshake_rejected_and_session_kept() {
        // 无一次性预密钥时,重放首条握手不得重置会话。
        let mut alice = ClientManager::new(0);
        let mut bob = ClientManager::new(0);
        alice.start_session("bob", &published_bundle(&bob)).unwrap();

        let m1 = alice.encrypt("bob", b"hello").unwrap();
        assert_eq!(dec(&mut bob, "alice", &m1).unwrap(), b"hello");
        let r1 = bob.encrypt("alice", b"hi").unwrap();
        assert_eq!(dec(&mut alice, "bob", &r1).unwrap(), b"hi");

        // 重放:同一握手 + 已消费的消息密钥 → 失败
        assert!(dec(&mut bob, "alice", &m1).is_err());

        // 会话不受影响
        let m2 = alice.encrypt("bob", b"still works").unwrap();
        assert_eq!(dec(&mut bob, "alice", &m2).unwrap(), b"still works");
    }

    #[test]
    fn forged_message_does_not_break_session() {
        let mut alice = ClientManager::new(5);
        let mut bob = ClientManager::new(5);
        alice.start_session("bob", &published_bundle(&bob)).unwrap();
        let m1 = alice.encrypt("bob", b"hello").unwrap();
        dec(&mut bob, "alice", &m1).unwrap();
        let r1 = bob.encrypt("alice", b"hi").unwrap();
        dec(&mut alice, "bob", &r1).unwrap();

        // 攻击者伪造一条带新 DH 公钥的消息
        let forged = RatchetMessage {
            header: crate::ratchet::Header { dh: [9u8; 32], pn: 0, n: 0 },
            ciphertext: vec![0u8; 40],
        };
        assert!(bob
            .decrypt("alice", EnvelopeType::Message, &wire::encode_message(&forged))
            .is_err());

        // 合法消息仍能正常解密(状态未被伪造消息推进)
        let m2 = alice.encrypt("bob", b"after forgery").unwrap();
        assert_eq!(dec(&mut bob, "alice", &m2).unwrap(), b"after forgery");
    }

    #[test]
    fn failed_handshake_keeps_one_time_prekey() {
        let mut alice = ClientManager::new(5);
        let mut bob = ClientManager::new(5);
        alice.start_session("bob", &published_bundle(&bob)).unwrap();
        let (t, mut p) = alice.encrypt("bob", b"hello").unwrap();
        let before = bob.one_time_prekeys().len();

        // 篡改密文尾部 → 解密失败,不得消费一次性预密钥,也不得留下会话
        let last = p.len() - 1;
        p[last] ^= 0xFF;
        assert!(bob.decrypt("alice", t, &p).is_err());
        assert_eq!(bob.one_time_prekeys().len(), before);
        assert!(!bob.has_session("alice"));
    }

    #[test]
    fn peer_reset_recovers_and_flags_identity_change() {
        // Bob 清空本地数据后以新身份重新上线:Alice 应能与之重建会话,并得到身份变化提示。
        let mut alice = ClientManager::new(5);
        let mut bob = ClientManager::new(5);
        alice.start_session("bob", &published_bundle(&bob)).unwrap();
        let m1 = alice.encrypt("bob", b"hello").unwrap();
        dec(&mut bob, "alice", &m1).unwrap();
        let r1 = bob.encrypt("alice", b"hi").unwrap();
        dec(&mut alice, "bob", &r1).unwrap();
        let old_number = alice.safety_number("bob").unwrap();

        let mut bob2 = ClientManager::new(5);
        // Alice 仍用旧会话发来的消息,新 Bob 无法解密(上层据此重新握手)
        let stale = alice.encrypt("bob", b"stale").unwrap();
        assert!(matches!(
            bob2.decrypt("alice", stale.0, &stale.1),
            Err(CryptoError::NoSession)
        ));

        bob2.start_session("alice", &published_bundle(&alice)).unwrap();
        let n1 = bob2.encrypt("alice", b"I'm back").unwrap();
        let d = alice.decrypt("bob", n1.0, &n1.1).unwrap();
        assert_eq!(d.plaintext, b"I'm back");
        assert!(d.identity_changed, "对端身份变化必须被报告");
        assert_ne!(alice.safety_number("bob").unwrap(), old_number);

        let a2 = alice.encrypt("bob", b"welcome back").unwrap();
        assert_eq!(a2.0, EnvelopeType::Message);
        assert_eq!(dec(&mut bob2, "alice", &a2).unwrap(), b"welcome back");
    }

    #[test]
    fn unknown_one_time_prekey_rejected() {
        let mut alice = ClientManager::new(5);
        let bob = ClientManager::new(5);
        let mut bob_other = ClientManager::new(0);
        alice.start_session("bob", &published_bundle(&bob)).unwrap();
        let m = alice.encrypt("bob", b"x").unwrap();
        assert!(matches!(
            bob_other.decrypt("alice", m.0, &m.1),
            Err(CryptoError::UnknownPreKey)
        ));
    }

    #[test]
    fn replenished_prekeys_have_fresh_ids() {
        let mut m = ClientManager::new(3);
        let ids: Vec<u32> = m.generate_one_time_prekeys(4).iter().map(|o| o.id).collect();
        assert_eq!(ids, vec![4, 5, 6, 7]);
        let all: HashSet<u32> = m.one_time_prekeys().iter().map(|o| o.id).collect();
        assert_eq!(all.len(), 7);

        // 重启后编号继续递增
        let mut m2 = ClientManager::from_bytes(&m.to_bytes().unwrap()).unwrap();
        assert_eq!(m2.generate_one_time_prekeys(1)[0].id, 8);
    }

    #[test]
    fn manager_persistence_round_trip() {
        let mut alice = ClientManager::new(5);
        let mut bob = ClientManager::new(5);
        let bundle = published_bundle(&bob);
        alice.start_session("bob", &bundle).unwrap();

        let m1 = alice.encrypt("bob", b"hello").unwrap();
        dec(&mut bob, "alice", &m1).unwrap();

        // 序列化 → 反序列化后,棘轮状态应延续,仍能继续收发
        let mut alice2 = ClientManager::from_bytes(&alice.to_bytes().unwrap()).unwrap();
        let m2 = alice2.encrypt("bob", b"after restart").unwrap();
        assert_eq!(dec(&mut bob, "alice", &m2).unwrap(), b"after restart");

        let mut bob2 = ClientManager::from_bytes(&bob.to_bytes().unwrap()).unwrap();
        let r = bob2.encrypt("alice", b"reply after restart").unwrap();
        assert_eq!(dec(&mut alice2, "bob", &r).unwrap(), b"reply after restart");

        // 安全号码在恢复后仍一致
        assert_eq!(
            alice2.safety_number("bob").unwrap(),
            bob2.safety_number("alice").unwrap()
        );
    }

    #[test]
    fn legacy_format_is_migrated() {
        // 旧版本落盘的数据(无格式标记)应能加载并继续通信。
        let mut alice = ClientManager::new(5);
        let mut bob = ClientManager::new(5);
        alice.start_session("bob", &published_bundle(&bob)).unwrap();
        let m1 = alice.encrypt("bob", b"hello").unwrap();
        dec(&mut bob, "alice", &m1).unwrap();

        let ClientManager {
            identity,
            signed_prekey,
            pq_prekey,
            one_time_prekeys,
            mut sessions,
            peers,
            ..
        } = bob;
        let legacy = LegacyClientManager {
            identity,
            signed_prekey,
            pq_prekey,
            one_time_prekeys,
            sessions: sessions
                .drain()
                .map(|(k, mut v)| (k, v.remove(0).session))
                .collect(),
            peers,
            pending: HashMap::new(),
        };
        let bytes = bincode::serialize(&legacy).unwrap();

        let mut bob2 = ClientManager::from_bytes(&bytes).unwrap();
        let m2 = alice.encrypt("bob", b"after upgrade").unwrap();
        assert_eq!(dec(&mut bob2, "alice", &m2).unwrap(), b"after upgrade");
        let r = bob2.encrypt("alice", b"reply").unwrap();
        assert_eq!(dec(&mut alice, "bob", &r).unwrap(), b"reply");
        assert!(bob2.generate_one_time_prekeys(1)[0].id > 100);
    }

    #[test]
    fn envelope_label_roundtrip() {
        assert_eq!(EnvelopeType::Prekey.label(), "prekey");
        assert_eq!(EnvelopeType::from_label("message").unwrap(), EnvelopeType::Message);
        assert!(EnvelopeType::from_label("bogus").is_err());
    }
}
