//! crypto-core 端到端集成测试:完整的 PQXDH 握手 + 双棘轮会话。

use crypto_core::fingerprint::safety_number;
use crypto_core::keys::{IdentityKeyPair, OneTimePreKey, PqPreKey, PreKeyBundle, SignedPreKey};
use crypto_core::session::Session;

/// 响应方(Bob)持有的全部密钥。
struct Responder {
    identity: IdentityKeyPair,
    spk: SignedPreKey,
    opk: OneTimePreKey,
    pq: PqPreKey,
}

fn setup_responder() -> Responder {
    let identity = IdentityKeyPair::generate();
    let spk = SignedPreKey::generate(&identity, 1);
    let opk = OneTimePreKey::generate(1);
    let pq = PqPreKey::generate(&identity, 1);
    Responder {
        identity,
        spk,
        opk,
        pq,
    }
}

fn bundle_with_opk(bob: &Responder) -> PreKeyBundle {
    PreKeyBundle::assemble(bob.identity.public(), &bob.spk, Some(&bob.opk), &bob.pq)
}

#[test]
fn full_session_bidirectional() {
    let bob = setup_responder();
    let alice_id = IdentityKeyPair::generate();

    let (mut alice, initial) = Session::initiate(&alice_id, &bundle_with_opk(&bob)).unwrap();
    let m1 = alice.encrypt("你好,Bob".as_bytes()).unwrap();

    let mut bob_session =
        Session::respond(&bob.identity, &bob.spk, Some(&bob.opk), &bob.pq, &initial).unwrap();
    assert_eq!(bob_session.decrypt(&m1).unwrap(), "你好,Bob".as_bytes());

    // 来回多轮,触发双棘轮推进
    let r1 = bob_session.encrypt("你好,Alice".as_bytes()).unwrap();
    assert_eq!(alice.decrypt(&r1).unwrap(), "你好,Alice".as_bytes());

    let m2 = alice.encrypt(b"how are you").unwrap();
    assert_eq!(bob_session.decrypt(&m2).unwrap(), b"how are you");

    let r2 = bob_session.encrypt(b"doing great").unwrap();
    assert_eq!(alice.decrypt(&r2).unwrap(), b"doing great");

    let m3 = alice.encrypt(b"bye").unwrap();
    assert_eq!(bob_session.decrypt(&m3).unwrap(), b"bye");
}

#[test]
fn out_of_order_delivery() {
    let bob = setup_responder();
    let alice_id = IdentityKeyPair::generate();

    let (mut alice, initial) = Session::initiate(&alice_id, &bundle_with_opk(&bob)).unwrap();
    let m0 = alice.encrypt(b"m0").unwrap();
    let m1 = alice.encrypt(b"m1").unwrap();
    let m2 = alice.encrypt(b"m2").unwrap();

    let mut bob_session =
        Session::respond(&bob.identity, &bob.spk, Some(&bob.opk), &bob.pq, &initial).unwrap();

    // 乱序到达:m0, m2, m1
    assert_eq!(bob_session.decrypt(&m0).unwrap(), b"m0");
    assert_eq!(bob_session.decrypt(&m2).unwrap(), b"m2");
    assert_eq!(bob_session.decrypt(&m1).unwrap(), b"m1");
}

#[test]
fn works_without_one_time_prekey() {
    let bob = setup_responder();
    let alice_id = IdentityKeyPair::generate();
    let bundle = PreKeyBundle::assemble(bob.identity.public(), &bob.spk, None, &bob.pq);

    let (mut alice, initial) = Session::initiate(&alice_id, &bundle).unwrap();
    let m = alice.encrypt(b"no one-time prekey").unwrap();

    let mut bob_session =
        Session::respond(&bob.identity, &bob.spk, None, &bob.pq, &initial).unwrap();
    assert_eq!(bob_session.decrypt(&m).unwrap(), b"no one-time prekey");
}

#[test]
fn tampered_ciphertext_rejected() {
    let bob = setup_responder();
    let alice_id = IdentityKeyPair::generate();

    let (mut alice, initial) = Session::initiate(&alice_id, &bundle_with_opk(&bob)).unwrap();
    let mut m = alice.encrypt(b"secret").unwrap();
    m.ciphertext[0] ^= 0xFF;

    let mut bob_session =
        Session::respond(&bob.identity, &bob.spk, Some(&bob.opk), &bob.pq, &initial).unwrap();
    assert!(bob_session.decrypt(&m).is_err());
}

#[test]
fn tampered_prekey_bundle_rejected() {
    let bob = setup_responder();
    let alice_id = IdentityKeyPair::generate();

    let mut bundle = bundle_with_opk(&bob);
    bundle.spk_public[0] ^= 0xFF; // 篡改签名预密钥公钥 → 混合验签失败
    assert!(Session::initiate(&alice_id, &bundle).is_err());
}

#[test]
fn safety_numbers_match_both_sides() {
    let bob = setup_responder();
    let alice_id = IdentityKeyPair::generate();

    let a = safety_number(&alice_id.public(), &bob.identity.public());
    let b = safety_number(&bob.identity.public(), &alice_id.public());
    assert_eq!(a, b);
}

#[test]
fn responder_cannot_send_before_first_message() {
    let bob = setup_responder();
    let alice_id = IdentityKeyPair::generate();
    let (_alice, initial) = Session::initiate(&alice_id, &bundle_with_opk(&bob)).unwrap();
    let mut bob_session =
        Session::respond(&bob.identity, &bob.spk, Some(&bob.opk), &bob.pq, &initial).unwrap();
    // 响应方尚无发送链:应返回错误而不是 panic
    assert!(bob_session.encrypt(b"too early").is_err());
}

#[test]
fn mismatched_prekey_ids_rejected() {
    let bob = setup_responder();
    let alice_id = IdentityKeyPair::generate();
    let (_alice, mut initial) = Session::initiate(&alice_id, &bundle_with_opk(&bob)).unwrap();
    initial.used_spk_id = 99;
    assert!(Session::respond(&bob.identity, &bob.spk, Some(&bob.opk), &bob.pq, &initial).is_err());
}

#[test]
fn forged_header_does_not_desync_ratchet() {
    let bob = setup_responder();
    let alice_id = IdentityKeyPair::generate();
    let (mut alice, initial) = Session::initiate(&alice_id, &bundle_with_opk(&bob)).unwrap();
    let m0 = alice.encrypt(b"m0").unwrap();
    let mut bob_session =
        Session::respond(&bob.identity, &bob.spk, Some(&bob.opk), &bob.pq, &initial).unwrap();
    bob_session.decrypt(&m0).unwrap();

    // 伪造:新的 DH 公钥 + 巨大的 pn,企图推进对方棘轮
    let mut forged = alice.encrypt(b"x").unwrap();
    forged.header.dh = [7u8; 32];
    forged.header.pn = 500;
    assert!(bob_session.decrypt(&forged).is_err());

    let m2 = alice.encrypt(b"m2").unwrap();
    assert_eq!(bob_session.decrypt(&m2).unwrap(), b"m2");
}
