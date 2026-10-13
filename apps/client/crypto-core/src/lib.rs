//! 基于后量子混合密码的端到端加密即时通讯系统 —— 客户端密码学核心。
//!
//! 实现端到端加密所需的协议层:混合 PQXDH 握手、双棘轮、AEAD 消息加密、
//! 身份/预密钥与安全号码。底层密码原语来自经过审阅的成熟库,本 crate 只做协议组装。
//!
//! 典型用法见 `tests/e2e.rs`:响应方发布预密钥包,发起方据此异步建立会话,
//! 随后双方用双棘轮收发端到端加密消息。

pub mod aead;
pub mod classical;
pub mod error;
pub mod fingerprint;
pub mod kdf;
pub mod keys;
pub mod manager;
pub mod pqc;
pub mod pqxdh;
pub mod random;
pub mod ratchet;
pub mod session;
pub mod store;
pub mod wire;

pub use error::{CryptoError, Result};
pub use fingerprint::safety_number;
pub use keys::{
    IdentityKeyPair, IdentityPublic, OneTimePreKey, PqPreKey, PreKeyBundle, SignedPreKey,
};
pub use manager::{ClientManager, Decrypted, EnvelopeType};
pub use pqxdh::InitialMessage;
pub use ratchet::RatchetMessage;
pub use session::Session;
