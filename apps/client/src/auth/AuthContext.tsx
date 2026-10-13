import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";

import { fetchMe, login, logout, register } from "../api/auth";
import type { AuthResult, RegisterInput, User } from "../api/auth";
import { uploadKeys } from "../api/keys";
import { cryptoLock, cryptoUnlock, isDesktop } from "../crypto/core";
import { syncPrekeys } from "../crypto/prekeys";
import { tokenStore } from "./storage";

type Status = "loading" | "authenticated" | "unauthenticated";

interface AuthContextValue {
  status: Status;
  user: User | null;
  doLogin: (email: string, password: string) => Promise<void>;
  doRegister: (input: RegisterInput) => Promise<void>;
  doLogout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("loading");
  const [user, setUser] = useState<User | null>(null);

  // 启动引导。
  // 桌面端:每次启动都需重新登录,因为本地加密存储要用登录口令派生密钥解锁
  //         (令牌无法解锁本地库)——这也是更稳妥的安全姿态。
  // 浏览器端:若本地有令牌则静默恢复会话。
  useEffect(() => {
    let active = true;
    (async () => {
      if (isDesktop()) {
        setStatus("unauthenticated");
        return;
      }
      if (!tokenStore.getAccess() && !tokenStore.getRefresh()) {
        setStatus("unauthenticated");
        return;
      }
      try {
        const { user } = await fetchMe();
        if (!active) return;
        setUser(user);
        setStatus("authenticated");
      } catch {
        tokenStore.clear();
        if (!active) return;
        setStatus("unauthenticated");
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  // 桌面端:用口令解锁本地加密存储;首次(全新身份)则上传整套公钥。
  // 非首次也同步一次:补充耗尽的一次性预密钥,并在服务器缺失本机公钥时自愈
  // (例如首次上传因网络失败、或服务器数据被重置),否则他人将无法与本机建立会话。
  const unlockCrypto = async (userId: string, password: string) => {
    if (!isDesktop()) return;
    const { fresh, bundle } = await cryptoUnlock(userId, password);
    if (fresh && bundle) {
      await uploadKeys(bundle);
      return;
    }
    try {
      await syncPrekeys(true);
    } catch (e) {
      console.warn("同步预密钥失败", e);
    }
  };

  // 先写入令牌(上传公钥需要鉴权),再用口令解锁本地库,最后才进入已认证态
  // (保证聊天界面挂载时密码学状态已就绪)。
  const finishAuth = async (result: AuthResult, password: string) => {
    tokenStore.set(result.access_token, result.refresh_token);
    await unlockCrypto(result.user.id, password);
    setUser(result.user);
    setStatus("authenticated");
  };

  const doLogin = async (email: string, password: string) => {
    await finishAuth(await login(email, password), password);
  };

  const doRegister = async (input: RegisterInput) => {
    await finishAuth(await register(input), input.password);
  };

  const doLogout = async () => {
    const refreshToken = tokenStore.getRefresh();
    tokenStore.clear();
    setUser(null);
    setStatus("unauthenticated");
    if (isDesktop()) {
      try {
        await cryptoLock();
      } catch {
        // 忽略
      }
    }
    if (refreshToken) {
      try {
        await logout(refreshToken);
      } catch {
        // 退出失败不影响本地登出
      }
    }
  };

  return (
    <AuthContext.Provider value={{ status, user, doLogin, doRegister, doLogout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth 必须在 AuthProvider 内使用");
  }
  return ctx;
}
