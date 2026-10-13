// 基于后量子混合密码的端到端加密即时通讯系统 —— 桌面客户端核心。
//
// crypto 模块承载 E2EE(PQXDH / 双棘轮 / AEAD)与会话状态。
// 私钥与明文只存在于此进程,不进入前端 JS 层。

mod crypto;
mod store;

/// 返回客户端版本号,供前端展示。
#[tauri::command]
fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// 应用入口:由 main.rs(桌面)与 mobile_entry_point(移动端)共同复用。
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(crypto::AppCrypto::default())
        .invoke_handler(tauri::generate_handler![
            app_version,
            crypto::crypto_unlock,
            crypto::crypto_lock,
            crypto::crypto_ready,
            crypto::crypto_prekey_upload,
            crypto::crypto_start_session,
            crypto::crypto_has_session,
            crypto::crypto_encrypt,
            crypto::crypto_decrypt,
            crypto::crypto_safety_number,
            crypto::store_save_messages,
            crypto::store_load_messages,
            crypto::media_encrypt,
            crypto::media_decrypt,
        ])
        .run(tauri::generate_context!())
        .expect("运行 Tauri 应用失败");
}
