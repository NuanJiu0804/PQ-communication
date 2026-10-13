//! 后量子原语薄封装:ML-KEM-768(KEM,FIPS 203)与 ML-DSA-65(签名,FIPS 204)。
//!
//! 仅在本模块依赖具体实现(RustCrypto `ml-kem` / `ml-dsa`)。协议层只通过这里的
//! 字节接口使用后量子原语,便于将来在不改动协议的前提下替换底层实现(如换成 liboqs)。

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, Key, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768, Seed as KemSeed};

use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{
    B32 as DsaSeed, EncodedVerifyingKey, Generate, Keypair, MlDsa65, Signature, SigningKey,
    VerifyingKey,
};

use crate::error::{CryptoError, Result};

/// ML-KEM-768 公钥(封装密钥)字节长度。
pub const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 密文字节长度。
pub const MLKEM768_CT_LEN: usize = 1088;
/// ML-KEM-768 私钥种子字节长度。
pub const MLKEM768_SEED_LEN: usize = 64;
/// KEM 共享密钥字节长度。
pub const KEM_SHARED_LEN: usize = 32;

/// ML-DSA-65 验证公钥字节长度。
pub const MLDSA65_VK_LEN: usize = 1952;
/// ML-DSA-65 签名字节长度。
pub const MLDSA65_SIG_LEN: usize = 3309;
/// ML-DSA-65 私钥种子字节长度。
pub const MLDSA65_SEED_LEN: usize = 32;

/// 一对 ML-KEM-768 密钥:私钥以 64 字节种子形式存储,公钥为 1184 字节。
pub struct KemKeypair {
    /// 私钥种子(密钥材料,需妥善保管)。
    pub secret_seed: [u8; MLKEM768_SEED_LEN],
    /// 公钥(封装密钥)字节。
    pub public_ek: Vec<u8>,
}

/// 生成一对 ML-KEM-768 密钥。
pub fn kem_generate() -> KemKeypair {
    let (dk, ek) = MlKem768::generate_keypair();
    let seed = dk.to_seed().expect("新生成的密钥应当带有种子");
    let mut secret_seed = [0u8; MLKEM768_SEED_LEN];
    secret_seed.copy_from_slice(seed.as_slice());
    KemKeypair {
        secret_seed,
        public_ek: ek.to_bytes().as_slice().to_vec(),
    }
}

/// 用对方的 ML-KEM-768 公钥封装,得到密文与共享密钥。
pub fn kem_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; KEM_SHARED_LEN])> {
    let key: Key<EncapsulationKey<MlKem768>> =
        Array::try_from(ek_bytes).map_err(|_| CryptoError::InvalidKey)?;
    let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| CryptoError::InvalidKey)?;
    let (ct, shared) = ek.encapsulate();
    let mut s = [0u8; KEM_SHARED_LEN];
    s.copy_from_slice(shared.as_slice());
    Ok((ct.as_slice().to_vec(), s))
}

/// 用自己的 ML-KEM-768 私钥种子解封装密文,得到共享密钥。
pub fn kem_decapsulate(
    secret_seed: &[u8; MLKEM768_SEED_LEN],
    ct_bytes: &[u8],
) -> Result<[u8; KEM_SHARED_LEN]> {
    let seed: KemSeed = Array::try_from(&secret_seed[..]).map_err(|_| CryptoError::InvalidKey)?;
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    let shared = dk
        .decapsulate_slice(ct_bytes)
        .map_err(|_| CryptoError::InvalidCiphertext)?;
    let mut s = [0u8; KEM_SHARED_LEN];
    s.copy_from_slice(shared.as_slice());
    Ok(s)
}

/// 一对 ML-DSA-65 密钥:私钥以 32 字节种子形式存储,公钥为 1952 字节。
pub struct DsaKeypair {
    /// 私钥种子(密钥材料,需妥善保管)。
    pub secret_seed: [u8; MLDSA65_SEED_LEN],
    /// 验证公钥字节。
    pub public_vk: Vec<u8>,
}

/// 生成一对 ML-DSA-65 密钥。
pub fn dsa_generate() -> DsaKeypair {
    let sk = SigningKey::<MlDsa65>::generate();
    let seed = sk.to_seed();
    let vk = sk.verifying_key();
    let mut secret_seed = [0u8; MLDSA65_SEED_LEN];
    secret_seed.copy_from_slice(seed.as_slice());
    DsaKeypair {
        secret_seed,
        public_vk: vk.encode().as_slice().to_vec(),
    }
}

/// 由 ML-DSA-65 私钥种子推导验证公钥字节。
pub fn dsa_public(secret_seed: &[u8; MLDSA65_SEED_LEN]) -> Vec<u8> {
    let seed: DsaSeed = Array::from(*secret_seed);
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    sk.verifying_key().encode().as_slice().to_vec()
}

/// 用 ML-DSA-65 私钥种子对消息签名。
pub fn dsa_sign(secret_seed: &[u8; MLDSA65_SEED_LEN], msg: &[u8]) -> Vec<u8> {
    let seed: DsaSeed = Array::from(*secret_seed);
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let sig: Signature<MlDsa65> = sk.sign(msg);
    sig.encode().as_slice().to_vec()
}

/// 用 ML-DSA-65 验证公钥校验签名。
pub fn dsa_verify(vk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    let vk_arr: EncodedVerifyingKey<MlDsa65> = match Array::try_from(vk_bytes) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_arr);
    let sig = match Signature::<MlDsa65>::try_from(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_round_trip() {
        let kp = kem_generate();
        assert_eq!(kp.public_ek.len(), MLKEM768_EK_LEN);
        let (ct, s_send) = kem_encapsulate(&kp.public_ek).unwrap();
        assert_eq!(ct.len(), MLKEM768_CT_LEN);
        let s_recv = kem_decapsulate(&kp.secret_seed, &ct).unwrap();
        assert_eq!(s_send, s_recv, "封装与解封装应得到相同共享密钥");
    }

    #[test]
    fn kem_rejects_bad_ek() {
        assert!(kem_encapsulate(&[0u8; 10]).is_err());
    }

    #[test]
    fn dsa_sign_verify() {
        let kp = dsa_generate();
        assert_eq!(kp.public_vk.len(), MLDSA65_VK_LEN);
        let msg = b"post-quantum signature test";
        let sig = dsa_sign(&kp.secret_seed, msg);
        assert_eq!(sig.len(), MLDSA65_SIG_LEN);
        assert!(dsa_verify(&kp.public_vk, msg, &sig));
        assert!(!dsa_verify(&kp.public_vk, b"different message", &sig));

        let mut tampered = sig.clone();
        tampered[0] ^= 0xFF;
        assert!(!dsa_verify(&kp.public_vk, msg, &tampered));
    }
}
