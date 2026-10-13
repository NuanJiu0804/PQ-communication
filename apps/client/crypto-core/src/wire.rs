//! 网络线格式:把握手头与棘轮消息序列化为紧凑字节,便于经服务器中继。
//!
//! 手写小端二进制编码(长度前缀 + 定长字段),不引入额外序列化依赖。
//! 服务器视这些字节为不透明负载。

use crate::error::{CryptoError, Result};
use crate::keys::IdentityPublic;
use crate::pqxdh::InitialMessage;
use crate::ratchet::{Header, RatchetMessage};

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    put_u32(buf, b.len() as u32);
    buf.extend_from_slice(b);
}

/// 顺序读取器,越界即报 InvalidMessage。
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    fn u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes(s.try_into().unwrap()))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(CryptoError::InvalidMessage)?;
        if end > self.b.len() {
            return Err(CryptoError::InvalidMessage);
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn array32(&mut self) -> Result<[u8; 32]> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }

    fn rest(&self) -> &'a [u8] {
        &self.b[self.pos..]
    }
}

fn put_identity(buf: &mut Vec<u8>, id: &IdentityPublic) {
    buf.extend_from_slice(&id.ik_ed);
    buf.extend_from_slice(&id.ik_x);
    put_bytes(buf, &id.ik_mldsa);
}

fn read_identity(r: &mut Reader) -> Result<IdentityPublic> {
    let ik_ed = r.array32()?;
    let ik_x = r.array32()?;
    let ik_mldsa = r.bytes()?;
    Ok(IdentityPublic { ik_ed, ik_x, ik_mldsa })
}

/// 编码握手头(InitialMessage)。
pub fn encode_initial(m: &InitialMessage) -> Vec<u8> {
    let mut b = Vec::new();
    put_identity(&mut b, &m.identity);
    b.extend_from_slice(&m.ephemeral_public);
    put_u32(&mut b, m.used_spk_id);
    match m.used_opk_id {
        Some(id) => {
            b.push(1);
            put_u32(&mut b, id);
        }
        None => b.push(0),
    }
    put_u32(&mut b, m.used_pq_id);
    put_bytes(&mut b, &m.kem_ciphertext);
    b
}

/// 解码握手头。
pub fn decode_initial(data: &[u8]) -> Result<InitialMessage> {
    let mut r = Reader::new(data);
    let identity = read_identity(&mut r)?;
    let ephemeral_public = r.array32()?;
    let used_spk_id = r.u32()?;
    let used_opk_id = if r.take(1)?[0] == 1 { Some(r.u32()?) } else { None };
    let used_pq_id = r.u32()?;
    let kem_ciphertext = r.bytes()?;
    Ok(InitialMessage {
        identity,
        ephemeral_public,
        used_spk_id,
        used_opk_id,
        used_pq_id,
        kem_ciphertext,
    })
}

/// 编码棘轮消息(RatchetMessage)。
pub fn encode_message(m: &RatchetMessage) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&m.header.dh);
    put_u32(&mut b, m.header.pn);
    put_u32(&mut b, m.header.n);
    put_bytes(&mut b, &m.ciphertext);
    b
}

/// 解码棘轮消息。
pub fn decode_message(data: &[u8]) -> Result<RatchetMessage> {
    let mut r = Reader::new(data);
    let dh = r.array32()?;
    let pn = r.u32()?;
    let n = r.u32()?;
    let ciphertext = r.bytes()?;
    Ok(RatchetMessage {
        header: Header { dh, pn, n },
        ciphertext,
    })
}

/// 编码首条 prekey 负载:长度前缀的握手头 + 紧随其后的棘轮消息。
pub fn encode_prekey_payload(initial: &InitialMessage, message: &RatchetMessage) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, &encode_initial(initial));
    out.extend_from_slice(&encode_message(message));
    out
}

/// 解码首条 prekey 负载。
pub fn decode_prekey_payload(data: &[u8]) -> Result<(InitialMessage, RatchetMessage)> {
    let mut r = Reader::new(data);
    let initial_bytes = r.bytes()?;
    let initial = decode_initial(&initial_bytes)?;
    let message = decode_message(r.rest())?;
    Ok((initial, message))
}
