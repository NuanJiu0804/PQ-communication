import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { ShieldCheck, LogOut, RefreshCw, Lock } from "lucide-react";

import * as api from "./api";
import { ApiError, adminToken } from "./api";
import type { AuditRow, MessageMeta, Stats, UserRow } from "./api";

const shortId = (id: string) => (id ? id.slice(0, 8) + "…" : "—");
const fmt = (iso: string) => new Date(iso).toLocaleString();

export default function App() {
  const [token, setToken] = useState<string | null>(adminToken.get());

  const logout = useCallback(() => {
    adminToken.clear();
    setToken(null);
  }, []);

  if (!token) {
    return <LoginView onLogin={(t) => setToken(t)} />;
  }
  return <Dashboard onLogout={logout} />;
}

function LoginView({ onLogin }: { onLogin: (token: string) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const r = await api.login(username, password);
      adminToken.set(r.access_token);
      onLogin(r.access_token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="login-head">
          <ShieldCheck className="mark" size={22} aria-hidden />
          <span className="login-title">管理后台</span>
        </div>
        <p className="login-sub">基于后量子混合密码的端到端加密即时通讯系统</p>
        <p className="login-sub">仅可查看元数据与不可读密文,无任何解密能力</p>
        {error ? <div className="alert-error">{error}</div> : null}
        <div className="field">
          <label htmlFor="u">用户名</label>
          <input id="u" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        </div>
        <div className="field">
          <label htmlFor="p">密码</label>
          <input id="p" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
        </div>
        <button className="btn btn-full" type="submit" disabled={busy}>
          {busy ? "登录中…" : "登录"}
        </button>
      </form>
    </div>
  );
}

type Tab = "overview" | "messages" | "users" | "audit";

function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [tab, setTab] = useState<Tab>("overview");

  // 任意接口 401(令牌失效)即登出
  const guard = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) onLogout();
    },
    [onLogout],
  );

  return (
    <div className="app">
      <div className="topbar">
        <div className="brand">
          <ShieldCheck className="mark" size={20} aria-hidden />
          基于后量子混合密码的端到端加密即时通讯系统 · 管理后台
          <span className="tag">隐私可证</span>
        </div>
        <button className="btn btn-sm" onClick={onLogout}>
          <LogOut size={14} aria-hidden /> 退出
        </button>
      </div>
      <nav className="nav">
        {(
          [
            ["overview", "概览"],
            ["messages", "转发消息"],
            ["users", "用户管理"],
            ["audit", "审计日志"],
          ] as [Tab, string][]
        ).map(([k, label]) => (
          <button key={k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>
            {label}
          </button>
        ))}
      </nav>
      <div className="content">
        {tab === "overview" && <Overview onError={guard} />}
        {tab === "messages" && <Messages onError={guard} />}
        {tab === "users" && <Users onError={guard} />}
        {tab === "audit" && <Audit onError={guard} />}
      </div>
    </div>
  );
}

function useFetch<T>(fn: () => Promise<T>, onError: (e: unknown) => void) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    setError(null);
    try {
      setData(await fn());
    } catch (e) {
      onError(e);
      setError(e instanceof Error ? e.message : "加载失败");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onError]);
  useEffect(() => {
    void load();
  }, [load]);
  return { data, error, reload: load };
}

function RefreshBar({ onClick }: { onClick: () => void }) {
  return (
    <div className="refresh">
      <button className="btn btn-sm" onClick={onClick}>
        <RefreshCw size={14} aria-hidden /> 刷新
      </button>
    </div>
  );
}

function Overview({ onError }: { onError: (e: unknown) => void }) {
  const { data, error, reload } = useFetch<Stats>(api.fetchStats, onError);
  return (
    <>
      <RefreshBar onClick={reload} />
      {error ? <div className="alert-error">{error}</div> : null}
      {data ? (
        <div className="cards">
          <Stat label="注册用户" value={data.registered_users} />
          <Stat label="在线用户" value={data.online_users} />
          <Stat label="已发布密钥用户" value={data.users_with_keys} />
          <Stat label="一次性预密钥池" value={data.one_time_prekeys_left} />
          <Stat label="群组数" value={data.groups} />
          <Stat label="转发消息总数" value={data.total_messages} />
          <Stat label="已送达" value={data.delivered_messages} />
          <Stat label="离线暂存" value={data.queued_messages} />
        </div>
      ) : (
        <div className="empty">加载中…</div>
      )}
    </>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="card">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
    </div>
  );
}

function Messages({ onError }: { onError: (e: unknown) => void }) {
  const { data, error, reload } = useFetch<{ messages: MessageMeta[] }>(api.fetchMessages, onError);
  return (
    <>
      <div className="proof-banner">
        <Lock className="mark" size={18} aria-hidden />
        <div>
          <strong>隐私证明:</strong>
          服务端转发的每条消息在这里都只是一段<strong>不可读的密文</strong>(下表「密文样本」列为前 48 字节)。
          服务器与管理员既无用户私钥、也无会话密钥,<strong>无法解密任何消息内容</strong>。
        </div>
      </div>
      <RefreshBar onClick={reload} />
      {error ? <div className="alert-error">{error}</div> : null}
      <div className="panel">
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>发送者</th>
              <th>接收者</th>
              <th>群</th>
              <th>类型</th>
              <th>密文大小</th>
              <th>密文样本(base64,不可读)</th>
              <th>状态</th>
            </tr>
          </thead>
          <tbody>
            {data && data.messages.length > 0 ? (
              data.messages.map((m) => (
                <tr key={m.id}>
                  <td>{fmt(m.created_at)}</td>
                  <td className="mono">{shortId(m.sender_id)}</td>
                  <td className="mono">{shortId(m.recipient_id)}</td>
                  <td className="mono">{m.group_id ? shortId(m.group_id) : <span className="muted">—</span>}</td>
                  <td>{m.envelope_type}</td>
                  <td>{m.ciphertext_size} B</td>
                  <td className="cipher" title={m.ciphertext_sample}>
                    {m.ciphertext_sample || <span className="muted">(已撤回,密文已清除)</span>}
                  </td>
                  <td>
                    <span className={`pill ${m.delivery_status}`}>{m.delivery_status}</span>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={8} className="empty">
                  {data ? "暂无转发消息" : "加载中…"}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Users({ onError }: { onError: (e: unknown) => void }) {
  const { data, error, reload } = useFetch<{ users: UserRow[] }>(api.fetchUsers, onError);

  const toggle = async (u: UserRow) => {
    try {
      if (u.is_banned) await api.unbanUser(u.id);
      else await api.banUser(u.id);
      await reload();
    } catch (e) {
      onError(e);
    }
  };

  return (
    <>
      <RefreshBar onClick={reload} />
      {error ? <div className="alert-error">{error}</div> : null}
      <div className="panel">
        <table>
          <thead>
            <tr>
              <th>邮箱</th>
              <th>昵称</th>
              <th>注册时间</th>
              <th>状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {data && data.users.length > 0 ? (
              data.users.map((u) => (
                <tr key={u.id}>
                  <td>{u.email}</td>
                  <td>{u.nickname}</td>
                  <td>{fmt(u.created_at)}</td>
                  <td>{u.is_banned ? <span className="pill banned">已封禁</span> : <span className="pill">正常</span>}</td>
                  <td>
                    <button className={`btn btn-sm ${u.is_banned ? "" : "btn-danger"}`} onClick={() => toggle(u)}>
                      {u.is_banned ? "解封" : "封禁"}
                    </button>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5} className="empty">
                  {data ? "暂无用户" : "加载中…"}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Audit({ onError }: { onError: (e: unknown) => void }) {
  const { data, error, reload } = useFetch<{ audit: AuditRow[] }>(api.fetchAudit, onError);
  return (
    <>
      <RefreshBar onClick={reload} />
      {error ? <div className="alert-error">{error}</div> : null}
      <div className="panel">
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>操作</th>
              <th>目标</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {data && data.audit.length > 0 ? (
              data.audit.map((a, i) => (
                <tr key={i}>
                  <td>{fmt(a.created_at)}</td>
                  <td>{a.action}</td>
                  <td className="mono">{a.target ? shortId(a.target) : <span className="muted">—</span>}</td>
                  <td className="mono">{a.ip || <span className="muted">—</span>}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={4} className="empty">
                  {data ? "暂无审计记录" : "加载中…"}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
