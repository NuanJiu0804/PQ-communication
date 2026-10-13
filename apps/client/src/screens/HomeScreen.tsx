import { LogOut } from "lucide-react";

import { Button } from "../components/Button";
import { useAuth } from "../auth/AuthContext";

export function HomeScreen() {
  const { user, doLogout } = useAuth();
  if (!user) return null;

  const initial = user.nickname.trim().slice(0, 1).toUpperCase() || "?";
  const joined = new Date(user.created_at).toLocaleString();

  return (
    <div className="home">
      <section className="profile-card">
        <div className="avatar" aria-hidden>
          {initial}
        </div>
        <div className="profile-name">{user.nickname}</div>
        <div className="profile-email mono">{user.email}</div>

        <dl className="profile-meta">
          <div className="meta-row">
            <dt>用户 ID</dt>
            <dd className="mono">{user.id}</dd>
          </div>
          <div className="meta-row">
            <dt>注册时间</dt>
            <dd className="mono">{joined}</dd>
          </div>
        </dl>

        <Button variant="ghost" className="logout-btn" onClick={() => void doLogout()}>
          <LogOut size={16} aria-hidden />
          退出登录
        </Button>
      </section>

      <p className="home-hint">
        账号体系已就绪。好友管理、单聊与端到端加密会话将在后续阶段接入,
        届时所有加解密都在本地 Rust 核心完成。
      </p>
    </div>
  );
}
