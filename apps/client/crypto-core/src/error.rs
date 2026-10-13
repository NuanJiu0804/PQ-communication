//! crypto-core 统一错误类型。

/// 密码学操作错误。
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// 公钥或私钥的字节表示无效。
    #[error("无效的密钥")]
    InvalidKey,
    /// KEM 密文无效。
    #[error("无效的密文")]
    InvalidCiphertext,
    /// 签名验证失败。
    #[error("签名验证失败")]
    InvalidSignature,
    /// AEAD 解密失败(数据被篡改或密钥不匹配)。
    #[error("解密失败:数据被篡改或密钥错误")]
    DecryptionFailed,
    /// 待处理的消息格式无效。
    #[error("消息格式无效")]
    InvalidMessage,
    /// 会话/棘轮状态无效。
    #[error("会话状态无效")]
    InvalidState,
    /// 预密钥包验签失败。
    #[error("预密钥包验证失败")]
    InvalidPrekeyBundle,
    /// 握手引用了本机不存在(或已被消费)的预密钥。
    #[error("握手引用的预密钥不存在或已被使用")]
    UnknownPreKey,
    /// 握手消息被重放(同一临时公钥的握手已处理过)。
    #[error("检测到重放的握手消息")]
    ReplayedHandshake,
    /// 尚未与该对端建立会话。
    #[error("NO_SESSION:尚未与对方建立会话")]
    NoSession,
}

/// crypto-core 的结果类型别名。
pub type Result<T> = core::result::Result<T, CryptoError>;
