// 管理后台 API 客户端。管理员令牌存 localStorage,经 Authorization: Bearer 发送。

const BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";
const TOKEN_KEY = "pqchat.admin_token";

export const adminToken = {
  get: (): string | null => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};

async function req<T>(path: string, opts: { method?: string; body?: unknown; auth?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = {};
  if (opts.body) headers["Content-Type"] = "application/json";
  if (opts.auth !== false) {
    const t = adminToken.get();
    if (t) headers["Authorization"] = `Bearer ${t}`;
  }
  const res = await fetch(`${BASE}${path}`, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new ApiError(res.status, (data && data.error) || `请求失败 (${res.status})`);
  }
  return data as T;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export interface Stats {
  registered_users: number;
  online_users: number;
  users_with_keys: number;
  one_time_prekeys_left: number;
  groups: number;
  total_messages: number;
  delivered_messages: number;
  queued_messages: number;
}

export interface MessageMeta {
  id: string;
  sender_id: string;
  recipient_id: string;
  group_id: string | null;
  envelope_type: string;
  ciphertext_size: number;
  ciphertext_sample: string;
  delivery_status: string;
  created_at: string;
}

export interface UserRow {
  id: string;
  email: string;
  nickname: string;
  is_banned: boolean;
  created_at: string;
}

export interface AuditRow {
  action: string;
  target: string;
  detail: string;
  ip: string;
  created_at: string;
}

export const login = (username: string, password: string) =>
  req<{ access_token: string; role: string; expires_at: number }>("/api/v1/admin/login", {
    method: "POST",
    auth: false,
    body: { username, password },
  });

export const fetchStats = () => req<Stats>("/api/v1/admin/stats");
export const fetchMessages = () => req<{ messages: MessageMeta[] }>("/api/v1/admin/messages?limit=50");
export const fetchUsers = () => req<{ users: UserRow[] }>("/api/v1/admin/users?limit=100");
export const banUser = (id: string) => req(`/api/v1/admin/users/${id}/ban`, { method: "POST" });
export const unbanUser = (id: string) => req(`/api/v1/admin/users/${id}/unban`, { method: "POST" });
export const fetchAudit = () => req<{ audit: AuditRow[] }>("/api/v1/admin/audit?limit=100");
