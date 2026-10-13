import { API_BASE_URL } from "../config";
import { tokenStore } from "../auth/storage";

// ApiError 携带 HTTP 状态码与服务端返回的中文错误信息。
export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  auth?: boolean; // 是否附带 access 令牌
  _retry?: boolean; // 内部:刷新后重试标记
}

function rawRequest(path: string, opts: RequestOptions): Promise<Response> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (opts.auth) {
    const token = tokenStore.getAccess();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }
  return fetch(`${API_BASE_URL}${path}`, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
}

let refreshing: Promise<boolean> | null = null;

// tryRefresh 使用刷新令牌换取新令牌;并发调用共享同一次刷新。
function tryRefresh(): Promise<boolean> {
  if (refreshing) {
    return refreshing;
  }
  const refreshToken = tokenStore.getRefresh();
  if (!refreshToken) {
    return Promise.resolve(false);
  }
  refreshing = (async () => {
    try {
      const res = await rawRequest("/api/v1/auth/refresh", {
        method: "POST",
        body: { refresh_token: refreshToken },
      });
      if (!res.ok) {
        tokenStore.clear();
        return false;
      }
      const data = (await res.json()) as { access_token: string; refresh_token: string };
      tokenStore.set(data.access_token, data.refresh_token);
      return true;
    } catch {
      return false;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

// apiRequest 发起请求并解析 JSON;对带鉴权的请求在 401 时自动刷新一次后重试。
export async function apiRequest<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  let res = await rawRequest(path, opts);

  if (res.status === 401 && opts.auth && !opts._retry) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      res = await rawRequest(path, { ...opts, _retry: true });
    }
  }

  const text = await res.text();
  const data = text ? JSON.parse(text) : null;

  if (!res.ok) {
    const message =
      (data && (data.error || data.message)) || `请求失败(${res.status})`;
    throw new ApiError(res.status, message);
  }
  return data as T;
}

// errorMessage 把异常转换为可展示的中文文案。
// Tauri 命令的错误是字符串;fetch 的网络错误是 TypeError;其余 Error 直接展示其消息。
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    return err.message;
  }
  if (typeof err === "string") {
    return err.replace(/^[A-Z_]+:/, "");
  }
  if (err instanceof TypeError) {
    return "无法连接服务器,请确认后端已启动";
  }
  if (err instanceof Error && err.message) {
    return err.message;
  }
  return "操作失败,请稍后重试";
}
