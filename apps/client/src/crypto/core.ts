// 对 Tauri Rust 核心暴露的密码学命令的封装。
// 这些命令只在桌面应用(Tauri)内可用;浏览器预览下不可用。

export function isDesktop(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function inv<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

/** 上传给服务器的公钥包(形状与后端 /keys/upload 一致)。前端只做透传。 */
export type UploadBundle = Record<string, unknown>;

/** 从服务器领取的预密钥包(形状与后端 /keys/bundle 一致)。 */
export type FetchedBundle = Record<string, unknown>;

export interface EnvelopeOut {
  envelope_type: string;
  payload: string;
}

export interface UnlockResult {
  fresh: boolean;
  bundle: UploadBundle | null;
}

/** 用登录用户与口令解锁本地加密存储(已有则恢复,首次返回需上传的公钥包)。 */
export const cryptoUnlock = (userId: string, password: string): Promise<UnlockResult> =>
  inv("crypto_unlock", { userId, password });

/** 登出时锁定本地存储,清空内存中的密钥与会话。 */
export const cryptoLock = (): Promise<void> => inv("crypto_lock");

/** 加密保存消息历史(JSON 字符串)。 */
export const storeSaveMessages = (json: string): Promise<void> =>
  inv("store_save_messages", { json });

/** 读取并解密消息历史(无则返回 null)。 */
export const storeLoadMessages = (): Promise<string | null> => inv("store_load_messages");

export const cryptoReady = (): Promise<boolean> => inv("crypto_ready");

/** 发起会话;返回对端身份是否与此前记录的不同(安全号码已变化)。 */
export const cryptoStartSession = (peerId: string, bundle: FetchedBundle): Promise<boolean> =>
  inv("crypto_start_session", { peerId, bundle });

/** 生成本次需上传的公钥包(服务器一次性预密钥不足时附带新补充的一批)。 */
export const cryptoPrekeyUpload = (serverCount: number): Promise<UploadBundle> =>
  inv("crypto_prekey_upload", { serverCount });

export const cryptoHasSession = (peerId: string): Promise<boolean> =>
  inv("crypto_has_session", { peerId });

export const cryptoEncrypt = (peerId: string, plaintext: string): Promise<EnvelopeOut> =>
  inv("crypto_encrypt", { peerId, plaintext });

export interface DecryptOut {
  plaintext: string;
  /** 对端身份密钥是否变化(需提醒用户重新核对安全号码)。 */
  identity_changed: boolean;
}

export const cryptoDecrypt = (
  peerId: string,
  envelopeType: string,
  payload: string,
): Promise<DecryptOut> => inv("crypto_decrypt", { peerId, envelopeType, payload });

/** Rust 核心在「尚未与对方建立会话」时返回的错误前缀。 */
export const isNoSessionError = (err: unknown): boolean =>
  typeof err === "string" && err.startsWith("NO_SESSION");

export const cryptoSafetyNumber = (peerId: string): Promise<string> =>
  inv("crypto_safety_number", { peerId });

export interface MediaSealed {
  ciphertext: string;
  key: string;
  nonce: string;
}

/** 用一次性随机密钥加密媒体字节(base64 进 / 出)。 */
export const mediaEncrypt = (dataBase64: string): Promise<MediaSealed> =>
  inv("media_encrypt", { data: dataBase64 });

/** 用媒体密钥与 nonce 解密媒体密文,返回明文字节的 base64。 */
export const mediaDecrypt = (ciphertext: string, key: string, nonce: string): Promise<string> =>
  inv("media_decrypt", { ciphertext, key, nonce });
