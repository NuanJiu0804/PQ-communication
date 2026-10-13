//! 论文实验数据:测量各密码原语与协议步骤的耗时及线上数据尺寸。
//! 运行:cargo run --release --example bench
use std::time::Instant;

use crypto_core::keys::{IdentityKeyPair, OneTimePreKey, PqPreKey, PreKeyBundle, SignedPreKey};
use crypto_core::session::Session;
use crypto_core::{classical, pqc, pqxdh, store, wire, ClientManager};

fn bench<F: FnMut()>(name: &str, iters: u32, mut f: F) {
    for _ in 0..(iters / 10).max(1) {
        f();
    }
    let mut samples = Vec::with_capacity(iters as usize);
    for _ in 0..iters {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_secs_f64() * 1e6);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let median = samples[samples.len() / 2];
    let p95 = samples[(samples.len() as f64 * 0.95) as usize];
    println!("TIME|{name}|{iters}|{mean:.2}|{median:.2}|{p95:.2}");
}

fn main() {
    let n = 2000;
    // ---- 经典原语 ----
    bench("X25519 密钥生成", n, || { classical::x25519_generate(); });
    let a = classical::x25519_generate();
    let b = classical::x25519_generate();
    bench("X25519 DH 计算", n, || { classical::x25519_dh(&a.secret, &b.public); });
    let ed = classical::ed25519_generate();
    bench("Ed25519 签名", n, || { classical::ed25519_sign(&ed.secret, b"prekey payload"); });
    let sig = classical::ed25519_sign(&ed.secret, b"prekey payload");
    bench("Ed25519 验签", n, || { classical::ed25519_verify(&ed.public, b"prekey payload", &sig); });

    // ---- 后量子原语 ----
    bench("ML-KEM-768 密钥生成", n, || { pqc::kem_generate(); });
    let kp = pqc::kem_generate();
    bench("ML-KEM-768 封装", n, || { pqc::kem_encapsulate(&kp.public_ek).unwrap(); });
    let (ct, _) = pqc::kem_encapsulate(&kp.public_ek).unwrap();
    bench("ML-KEM-768 解封装", n, || { pqc::kem_decapsulate(&kp.secret_seed, &ct).unwrap(); });
    bench("ML-DSA-65 密钥生成", 500, || { pqc::dsa_generate(); });
    let dk = pqc::dsa_generate();
    // ML-DSA 签名是确定性的,拒绝采样轮数取决于(密钥, 消息);用不同消息测量才能得到平均耗时
    let mut ctr: u64 = 0;
    bench("ML-DSA-65 签名", 3000, || {
        ctr += 1;
        pqc::dsa_sign(&dk.secret_seed, &ctr.to_le_bytes());
    });
    let dsig = pqc::dsa_sign(&dk.secret_seed, b"prekey payload");
    bench("ML-DSA-65 验签", 1000, || { pqc::dsa_verify(&dk.public_vk, b"prekey payload", &dsig); });

    // ---- 协议步骤 ----
    let bob_id = IdentityKeyPair::generate();
    let spk = SignedPreKey::generate(&bob_id, 1);
    let pq = PqPreKey::generate(&bob_id, 1);
    let opk = OneTimePreKey::generate(1);
    let bundle = PreKeyBundle::assemble(bob_id.public(), &spk, Some(&opk), &pq);
    let alice_id = IdentityKeyPair::generate();
    bench("预密钥包混合验签", 500, || { bundle.verify().unwrap(); });
    bench("混合 PQXDH 发起方(含验签)", 500, || { pqxdh::initiate(&alice_id, &bundle).unwrap(); });
    let (initial, _, _) = pqxdh::initiate(&alice_id, &bundle).unwrap();
    bench("混合 PQXDH 响应方", 500, || { pqxdh::respond(&bob_id, &spk, Some(&opk), &pq, &initial).unwrap(); });
    bench("经典部分(4 次 X25519)", 2000, || {
        for _ in 0..4 { classical::x25519_dh(&a.secret, &b.public); }
    });
    bench("新建客户端身份(含 20 个一次性预密钥)", 100, || { ClientManager::new(20); });

    let (mut alice, init) = Session::initiate(&alice_id, &bundle).unwrap();
    let first = alice.encrypt(b"hello").unwrap();
    let mut bob = Session::respond(&bob_id, &spk, Some(&opk), &pq, &init).unwrap();
    bob.decrypt(&first).unwrap();
    let msg = vec![0x61u8; 100];
    bench("双棘轮加密(100B,对称链)", n, || { alice.encrypt(&msg).unwrap(); });
    // 解密:新建一对会话,预先按序加密 n 条,再依次解密
    let (mut a2, init2) = Session::initiate(&alice_id, &bundle).unwrap();
    let f2 = a2.encrypt(b"hello").unwrap();
    let mut b2 = Session::respond(&bob_id, &spk, Some(&opk), &pq, &init2).unwrap();
    b2.decrypt(&f2).unwrap();
    let total = (n + n / 10 + 1) as usize;
    let mut fresh: Vec<_> = (0..total).map(|_| a2.encrypt(&msg).unwrap()).collect();
    fresh.reverse();
    bench("双棘轮解密(100B,对称链)", n, || { b2.decrypt(&fresh.pop().unwrap()).unwrap(); });
    drop(bob);
    let (mut alice, mut bob) = (a2, b2);
    // 含 DH 棘轮步:乒乓往返
    bench("双棘轮往返(含两次 DH 棘轮)", 1000, || {
        let m = alice.encrypt(&msg).unwrap();
        bob.decrypt(&m).unwrap();
        let r = bob.encrypt(&msg).unwrap();
        alice.decrypt(&r).unwrap();
    });

    let salt = store::generate_salt();
    bench("Argon2id 派生存储密钥", 20, || { store::derive_key(b"correct horse battery", &salt).unwrap(); });
    let key = [7u8; 32];
    let blob = vec![0u8; 64 * 1024];
    bench("本地存储封装 64KB", 500, || { store::seal(&key, &blob); });

    // ---- 尺寸 ----
    let init_bytes = wire::encode_initial(&initial);
    let m100 = alice.encrypt(&msg).unwrap();
    println!("SIZE|身份公钥(Ed25519+X25519+ML-DSA-65)|{}", 32 + 32 + bob_id.public().ik_mldsa.len());
    println!("SIZE|ML-KEM-768 公钥|{}", pq.public_ek.len());
    println!("SIZE|ML-KEM-768 密文|{}", ct.len());
    println!("SIZE|ML-DSA-65 签名|{}", dsig.len());
    println!("SIZE|预密钥包(公钥+签名合计)|{}",
        32 + 32 + bundle.identity.ik_mldsa.len() + 32 + 64 + bundle.spk_sig_mldsa.len() + 32 + bundle.pq_public_ek.len() + 64 + bundle.pq_sig_mldsa.len());
    println!("SIZE|握手头 InitialMessage|{}", init_bytes.len());
    println!("SIZE|100B 明文的常规消息|{}", wire::encode_message(&m100).len());
    println!("SIZE|100B 明文的 prekey 消息|{}", wire::encode_prekey_payload(&initial, &m100).len());
}
