// 账号会话令牌的存储。
//
// 说明:这里存的是「账号鉴权令牌」(JWT/刷新令牌),与 E2EE 密钥体系无关。
// E2EE 私钥与会话状态由 Rust 核心加密落盘(Argon2id + XChaCha20-Poly1305),从不进入 Web 存储。
//
// 使用 sessionStorage(按窗口隔离)而非 localStorage:同一台机器上同时运行的多个客户端窗口
// 共享 WebView 的 localStorage,若用 localStorage,第二个窗口登录会覆盖第一个窗口的令牌,
// 导致第一个窗口以他人身份调用接口。桌面端每次启动本就需要重新登录(口令用于解锁本地加密库),
// 令牌无需跨重启持久化。

const ACCESS_KEY = "pqchat.access_token";
const REFRESH_KEY = "pqchat.refresh_token";

export const tokenStore = {
  getAccess(): string | null {
    return sessionStorage.getItem(ACCESS_KEY);
  },
  getRefresh(): string | null {
    return sessionStorage.getItem(REFRESH_KEY);
  },
  set(access: string, refresh: string): void {
    sessionStorage.setItem(ACCESS_KEY, access);
    sessionStorage.setItem(REFRESH_KEY, refresh);
  },
  clear(): void {
    sessionStorage.removeItem(ACCESS_KEY);
    sessionStorage.removeItem(REFRESH_KEY);
  },
};
