//! 暴露给前端的密码学命令。所有加解密在此进程内完成,私钥与会话状态不进入 JS 层。
//!
//! 状态通过 SQLite + 应用层 AEAD 加密落盘(密钥由登录口令派生),重启后可恢复。
//! 与服务器交互的字节字段在 JS 边界统一用 base64 字符串(与后端 JSON 形状一致)。

use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};

use crypto_core::{
    aead, random, ClientManager, EnvelopeType, IdentityPublic, OneTimePreKey, PreKeyBundle,
};

use crate::store::SecureStore;

/// 每个身份生成的一次性预密钥数量。
const ONE_TIME_PREKEY_COUNT: u32 = 20;
/// 服务器剩余一次性预密钥低于该水位时补充。
const ONE_TIME_PREKEY_LOW_WATER: i64 = 5;
/// 单个媒体文件(明文)大小上限。
const MAX_MEDIA_BYTES: usize = 20 * 1024 * 1024;

/// 已解锁的应用密码学状态:管理器 + 加密存储。
pub struct UnlockedState {
    manager: ClientManager,
    store: SecureStore,
}

impl UnlockedState {
    /// 把当前管理器状态加密落盘。
    fn persist(&self) -> Result<(), String> {
        let bytes = self.manager.to_bytes().map_err(|e| e.to_string())?;
        self.store.put("manager", &bytes)
    }
}

/// 应用级密码学状态(单设备:一个管理器)。
#[derive(Default)]
pub struct AppCrypto(pub Mutex<Option<UnlockedState>>);

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(s).map_err(|_| "无效的 base64 数据".to_string())
}

fn to_arr<const N: usize>(v: Vec<u8>) -> Result<[u8; N], String> {
    v.try_into().map_err(|_| format!("字节长度应为 {N}"))
}

// ---- 上传(本机公钥 → 服务器)----

#[derive(Serialize)]
struct UploadIdentity {
    ik_ed: String,
    ik_x: String,
    ik_mldsa: String,
}

#[derive(Serialize)]
struct UploadSignedPreKey {
    id: i64,
    public: String,
    sig_ed: String,
    sig_mldsa: String,
}

#[derive(Serialize)]
struct UploadPqPreKey {
    id: i64,
    public_ek: String,
    sig_ed: String,
    sig_mldsa: String,
}

#[derive(Serialize)]
struct UploadOtpk {
    id: i64,
    public: String,
}

/// 上传给服务器的整套公钥(形状与后端 /keys/upload 一致)。
#[derive(Serialize)]
pub struct UploadBundle {
    identity: UploadIdentity,
    signed_prekey: UploadSignedPreKey,
    pq_prekey: UploadPqPreKey,
    one_time_prekeys: Vec<UploadOtpk>,
}

fn upload_bundle_from(m: &ClientManager, one_time: &[OneTimePreKey]) -> UploadBundle {
    let id = m.identity_public();
    let spk = m.signed_prekey();
    let pq = m.pq_prekey();
    UploadBundle {
        identity: UploadIdentity {
            ik_ed: b64(&id.ik_ed),
            ik_x: b64(&id.ik_x),
            ik_mldsa: b64(&id.ik_mldsa),
        },
        signed_prekey: UploadSignedPreKey {
            id: spk.id as i64,
            public: b64(&spk.public),
            sig_ed: b64(&spk.sig_ed),
            sig_mldsa: b64(&spk.sig_mldsa),
        },
        pq_prekey: UploadPqPreKey {
            id: pq.id as i64,
            public_ek: b64(&pq.public_ek),
            sig_ed: b64(&pq.sig_ed),
            sig_mldsa: b64(&pq.sig_mldsa),
        },
        one_time_prekeys: one_time
            .iter()
            .map(|o| UploadOtpk {
                id: o.id as i64,
                public: b64(&o.public),
            })
            .collect(),
    }
}

// ---- 领取(服务器 → 发起方)----

#[derive(Deserialize)]
struct FetchedIdentity {
    ik_ed: String,
    ik_x: String,
    ik_mldsa: String,
}

#[derive(Deserialize)]
struct FetchedSignedPreKey {
    id: i64,
    public: String,
    sig_ed: String,
    sig_mldsa: String,
}

#[derive(Deserialize)]
struct FetchedPqPreKey {
    id: i64,
    public_ek: String,
    sig_ed: String,
    sig_mldsa: String,
}

#[derive(Deserialize)]
struct FetchedOtpk {
    id: i64,
    public: String,
}

/// 从服务器领取的预密钥包(形状与后端 /keys/bundle 一致)。
#[derive(Deserialize)]
pub struct FetchedBundle {
    identity: FetchedIdentity,
    signed_prekey: FetchedSignedPreKey,
    pq_prekey: FetchedPqPreKey,
    one_time_prekey: Option<FetchedOtpk>,
}

impl FetchedBundle {
    fn into_core(self) -> Result<PreKeyBundle, String> {
        let identity = IdentityPublic {
            ik_ed: to_arr::<32>(unb64(&self.identity.ik_ed)?)?,
            ik_x: to_arr::<32>(unb64(&self.identity.ik_x)?)?,
            ik_mldsa: unb64(&self.identity.ik_mldsa)?,
        };
        let (opk_id, opk_public) = match self.one_time_prekey {
            Some(o) => (Some(o.id as u32), Some(to_arr::<32>(unb64(&o.public)?)?)),
            None => (None, None),
        };
        Ok(PreKeyBundle {
            identity,
            spk_id: self.signed_prekey.id as u32,
            spk_public: to_arr::<32>(unb64(&self.signed_prekey.public)?)?,
            spk_sig_ed: to_arr::<64>(unb64(&self.signed_prekey.sig_ed)?)?,
            spk_sig_mldsa: unb64(&self.signed_prekey.sig_mldsa)?,
            opk_id,
            opk_public,
            pq_id: self.pq_prekey.id as u32,
            pq_public_ek: unb64(&self.pq_prekey.public_ek)?,
            pq_sig_ed: to_arr::<64>(unb64(&self.pq_prekey.sig_ed)?)?,
            pq_sig_mldsa: unb64(&self.pq_prekey.sig_mldsa)?,
        })
    }
}

/// 加密输出:信封类型 + base64 负载。
#[derive(Serialize)]
pub struct EnvelopeOut {
    envelope_type: String,
    payload: String,
}

/// 解锁结果:是否首次(需上传公钥),以及首次时的上传包。
#[derive(Serialize)]
pub struct UnlockResult {
    fresh: bool,
    bundle: Option<UploadBundle>,
}

/// 解密输出:明文 + 对端身份是否变化(安全号码变化需提醒用户重新核对)。
#[derive(Serialize)]
pub struct DecryptOut {
    plaintext: String,
    identity_changed: bool,
}

/// 本地存储文件名只允许安全字符,防止 user_id 中的路径分隔符造成目录穿越。
fn store_file_name(user_id: &str) -> Result<String, String> {
    let ok = !user_id.is_empty()
        && user_id.len() <= 64
        && user_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok {
        Ok(format!("pqchat-{user_id}.db"))
    } else {
        Err("无效的用户 ID".to_string())
    }
}

// ---- 命令 ----

/// 用登录用户与口令解锁本地加密存储:
/// 已有则恢复身份/预密钥/会话;首次则生成并返回需上传给服务器的公钥包。
#[tauri::command]
pub fn crypto_unlock(
    app: tauri::AppHandle,
    state: State<'_, AppCrypto>,
    user_id: String,
    password: String,
) -> Result<UnlockResult, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "无法定位应用数据目录".to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let db_path = dir.join(store_file_name(&user_id)?);

    let store = SecureStore::unlock(&db_path, &password)?;

    match store.get("manager")? {
        Some(bytes) => {
            let manager = ClientManager::from_bytes(&bytes).map_err(|e| e.to_string())?;
            *state.0.lock().unwrap() = Some(UnlockedState { manager, store });
            Ok(UnlockResult { fresh: false, bundle: None })
        }
        None => {
            let manager = ClientManager::new(ONE_TIME_PREKEY_COUNT);
            let bundle = upload_bundle_from(&manager, manager.one_time_prekeys());
            let unlocked = UnlockedState { manager, store };
            unlocked.persist()?;
            *state.0.lock().unwrap() = Some(unlocked);
            Ok(UnlockResult { fresh: true, bundle: Some(bundle) })
        }
    }
}

/// 锁定(登出时清空内存中的解锁状态)。
#[tauri::command]
pub fn crypto_lock(state: State<'_, AppCrypto>) {
    *state.0.lock().unwrap() = None;
}

/// 是否已解锁密码学状态。
#[tauri::command]
pub fn crypto_ready(state: State<'_, AppCrypto>) -> bool {
    state.0.lock().unwrap().is_some()
}

/// 生成本次登录需要上传的公钥包:身份/签名预密钥/后量子预密钥(幂等覆盖,
/// 服务器数据丢失时可自愈),以及在服务器剩余一次性预密钥不足时补充的新一批。
/// 已上传过的一次性预密钥不会重复上传(它们可能已被服务器发放给他人)。
#[tauri::command]
pub fn crypto_prekey_upload(
    state: State<'_, AppCrypto>,
    server_count: i64,
) -> Result<UploadBundle, String> {
    let mut guard = state.0.lock().unwrap();
    let st = guard.as_mut().ok_or("密码学状态尚未解锁")?;
    if server_count >= ONE_TIME_PREKEY_LOW_WATER {
        return Ok(upload_bundle_from(&st.manager, &[]));
    }
    let fresh: Vec<OneTimePreKey> = st
        .manager
        .generate_one_time_prekeys(ONE_TIME_PREKEY_COUNT)
        .iter()
        .map(|o| OneTimePreKey { id: o.id, secret: o.secret, public: o.public })
        .collect();
    st.persist()?;
    Ok(upload_bundle_from(&st.manager, &fresh))
}

/// 发起方:据对方预密钥包建立会话。返回对端身份是否与此前记录的不同。
#[tauri::command]
pub fn crypto_start_session(
    state: State<'_, AppCrypto>,
    peer_id: String,
    bundle: FetchedBundle,
) -> Result<bool, String> {
    let pkb = bundle.into_core()?;
    let mut guard = state.0.lock().unwrap();
    let st = guard.as_mut().ok_or("密码学状态尚未解锁")?;
    let changed = st.manager.start_session(&peer_id, &pkb).map_err(|e| e.to_string())?;
    st.persist()?;
    Ok(changed)
}

/// 是否已与某对端建立会话。
#[tauri::command]
pub fn crypto_has_session(state: State<'_, AppCrypto>, peer_id: String) -> bool {
    state
        .0
        .lock()
        .unwrap()
        .as_ref()
        .map(|st| st.manager.has_session(&peer_id))
        .unwrap_or(false)
}

/// 加密一条明文,返回信封类型与 base64 负载。
#[tauri::command]
pub fn crypto_encrypt(
    state: State<'_, AppCrypto>,
    peer_id: String,
    plaintext: String,
) -> Result<EnvelopeOut, String> {
    let mut guard = state.0.lock().unwrap();
    let st = guard.as_mut().ok_or("密码学状态尚未解锁")?;
    let (env_type, payload) = st
        .manager
        .encrypt(&peer_id, plaintext.as_bytes())
        .map_err(|e| e.to_string())?;
    st.persist()?;
    Ok(EnvelopeOut {
        envelope_type: env_type.label().to_string(),
        payload: b64(&payload),
    })
}

/// 解密一条收到的负载,返回明文(UTF-8)与对端身份是否变化。
#[tauri::command]
pub fn crypto_decrypt(
    state: State<'_, AppCrypto>,
    peer_id: String,
    envelope_type: String,
    payload: String,
) -> Result<DecryptOut, String> {
    let env_type = EnvelopeType::from_label(&envelope_type).map_err(|e| e.to_string())?;
    let bytes = unb64(&payload)?;
    let mut guard = state.0.lock().unwrap();
    let st = guard.as_mut().ok_or("密码学状态尚未解锁")?;
    let out = st
        .manager
        .decrypt(&peer_id, env_type, &bytes)
        .map_err(|e| e.to_string())?;
    st.persist()?;
    Ok(DecryptOut {
        plaintext: String::from_utf8(out.plaintext).map_err(|_| "明文不是有效的 UTF-8".to_string())?,
        identity_changed: out.identity_changed,
    })
}

/// 与某对端的安全号码。
#[tauri::command]
pub fn crypto_safety_number(state: State<'_, AppCrypto>, peer_id: String) -> Result<String, String> {
    let guard = state.0.lock().unwrap();
    let st = guard.as_ref().ok_or("密码学状态尚未解锁")?;
    st.manager.safety_number(&peer_id).map_err(|e| e.to_string())
}

/// 媒体加密输出:密文 + 随机媒体密钥 + nonce(均 base64)。
/// 媒体密钥与 nonce 随 E2EE 文本消息发给对方;密文上传到 MinIO。
#[derive(Serialize)]
pub struct MediaSealed {
    ciphertext: String,
    key: String,
    nonce: String,
}

/// 用一次性随机密钥加密媒体字节(独立于会话棘轮),返回密文与密钥/nonce。
#[tauri::command]
pub fn media_encrypt(data: String) -> Result<MediaSealed, String> {
    let bytes = unb64(&data)?;
    if bytes.len() > MAX_MEDIA_BYTES {
        return Err(format!("文件过大(上限 {} MB)", MAX_MEDIA_BYTES / 1024 / 1024));
    }
    let key = random::random_array::<32>();
    let nonce = random::random_array::<24>();
    let ciphertext = aead::encrypt(&key, &nonce, &bytes, b"pqchat-media");
    Ok(MediaSealed {
        ciphertext: b64(&ciphertext),
        key: b64(&key),
        nonce: b64(&nonce),
    })
}

/// 用媒体密钥与 nonce 解密媒体密文,返回明文字节(base64)。
#[tauri::command]
pub fn media_decrypt(ciphertext: String, key: String, nonce: String) -> Result<String, String> {
    let k = to_arr::<32>(unb64(&key)?)?;
    let n = to_arr::<24>(unb64(&nonce)?)?;
    let ct = unb64(&ciphertext)?;
    let plain = aead::decrypt(&k, &n, &ct, b"pqchat-media").map_err(|e| e.to_string())?;
    Ok(b64(&plain))
}

/// 加密保存消息历史(前端传入 JSON 字符串)。
#[tauri::command]
pub fn store_save_messages(state: State<'_, AppCrypto>, json: String) -> Result<(), String> {
    let guard = state.0.lock().unwrap();
    let st = guard.as_ref().ok_or("密码学状态尚未解锁")?;
    st.store.put("messages", json.as_bytes())
}

/// 读取并解密消息历史(返回 JSON 字符串;无则 None)。
#[tauri::command]
pub fn store_load_messages(state: State<'_, AppCrypto>) -> Result<Option<String>, String> {
    let guard = state.0.lock().unwrap();
    let st = guard.as_ref().ok_or("密码学状态尚未解锁")?;
    match st.store.get("messages")? {
        Some(b) => Ok(Some(String::from_utf8(b).map_err(|_| "消息数据损坏".to_string())?)),
        None => Ok(None),
    }
}
