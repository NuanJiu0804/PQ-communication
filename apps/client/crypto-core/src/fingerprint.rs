//! 安全号码(指纹):用于带外核对双方身份公钥,防中间人。
//!
//! 对双方身份(经典 Ed25519/X25519 + 后量子 ML-DSA)分别取域分隔哈希,排序后
//! 一并哈希,渲染为 12 组、每组 5 位、共 60 位的可读数字串。双方算得的号码相同。

use sha2::{Digest, Sha512};

use crate::keys::IdentityPublic;

/// 计算两方之间的安全号码(可读数字串)。
pub fn safety_number(a: &IdentityPublic, b: &IdentityPublic) -> String {
    let fa = party_fingerprint(a);
    let fb = party_fingerprint(b);

    // 排序保证与「谁是 a/谁是 b」无关
    let (first, second) = if fa <= fb { (fa, fb) } else { (fb, fa) };

    let mut hasher = Sha512::new();
    hasher.update(b"PQChat-SafetyNumber-v1");
    hasher.update(first);
    hasher.update(second);
    let digest = hasher.finalize();

    render_digits(&digest)
}

/// 单方身份指纹:对身份各公钥做域分隔 SHA-512。
fn party_fingerprint(id: &IdentityPublic) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(b"PQChat-Identity-v1");
    hasher.update(id.ik_ed);
    hasher.update(id.ik_x);
    hasher.update(&id.ik_mldsa);
    let out = hasher.finalize();
    let mut fp = [0u8; 64];
    fp.copy_from_slice(&out);
    fp
}

/// 把哈希渲染成 12 组、每组 5 位数字,以空格分隔。
fn render_digits(digest: &[u8]) -> String {
    let mut groups = Vec::with_capacity(12);
    for i in 0..12 {
        let chunk = &digest[i * 5..i * 5 + 5];
        let mut value: u64 = 0;
        for &byte in chunk {
            value = (value << 8) | u64::from(byte);
        }
        groups.push(format!("{:05}", value % 100_000));
    }
    groups.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKeyPair;

    #[test]
    fn symmetric_and_stable() {
        let a = IdentityKeyPair::generate().public();
        let b = IdentityKeyPair::generate().public();
        let n1 = safety_number(&a, &b);
        let n2 = safety_number(&b, &a);
        assert_eq!(n1, n2, "双方算得的安全号码应一致");
        assert_eq!(safety_number(&a, &b), n1, "安全号码应稳定");
        // 12 组,每组 5 位,11 个空格
        assert_eq!(n1.split(' ').count(), 12);
        assert!(n1.split(' ').all(|g| g.len() == 5));
    }

    #[test]
    fn differs_for_different_identities() {
        let a = IdentityKeyPair::generate().public();
        let b = IdentityKeyPair::generate().public();
        let c = IdentityKeyPair::generate().public();
        assert_ne!(safety_number(&a, &b), safety_number(&a, &c));
    }
}
