import { useEffect, useState } from "react";
import type { FormEvent } from "react";

import { Button } from "../components/Button";
import { TextField } from "../components/TextField";
import { errorMessage } from "../api/client";
import { sendRegisterCode } from "../api/auth";
import { useAuth } from "../auth/AuthContext";

type Tab = "login" | "register";

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// 登录页动画插画:Claude 式的圆角徽章 + 火花,外圈光晕脉动、两点环绕、整体轻浮。
function AuthHero() {
  return (
    <div className="auth-hero" aria-hidden>
      <svg viewBox="0 0 100 100">
        <circle className="hero-glow" cx="50" cy="50" r="37" />
        <rect className="hero-badge" x="28" y="28" width="44" height="44" rx="13" />
        <g className="hero-spark">
          <path d="M50 32 C52 46 54 48 68 50 C54 52 52 54 50 68 C48 54 46 52 32 50 C46 48 48 46 50 32 Z" />
        </g>
        <g className="hero-orbit">
          <circle className="hero-dot" cx="50" cy="13" r="3.4" />
        </g>
        <g className="hero-orbit--rev">
          <circle className="hero-dot" cx="87" cy="50" r="2.6" opacity="0.7" />
        </g>
      </svg>
    </div>
  );
}

export function AuthScreen() {
  const [tab, setTab] = useState<Tab>("login");

  return (
    <div className="auth-card">
      <div className="auth-head">
        <AuthHero />
        <h1 className="auth-title">
          基于后量子混合密码的
          <br />
          端到端加密即时通讯系统
        </h1>
        <p className="auth-subtitle">登录以开始端到端加密通讯</p>
      </div>

      <div className="tabs" role="tablist">
        <button
          role="tab"
          aria-selected={tab === "login"}
          className={tab === "login" ? "tab active" : "tab"}
          onClick={() => setTab("login")}
        >
          登录
        </button>
        <button
          role="tab"
          aria-selected={tab === "register"}
          className={tab === "register" ? "tab active" : "tab"}
          onClick={() => setTab("register")}
        >
          注册
        </button>
      </div>

      {tab === "login" ? <LoginForm /> : <RegisterForm />}
    </div>
  );
}

function LoginForm() {
  const { doLogin } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await doLogin(email.trim(), password);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form className="auth-form" onSubmit={onSubmit} noValidate>
      {error ? <div className="alert alert-error">{error}</div> : null}
      <TextField
        label="邮箱"
        name="email"
        type="email"
        autoComplete="email"
        placeholder="you@example.com"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        required
      />
      <TextField
        label="密码"
        name="password"
        type="password"
        autoComplete="current-password"
        placeholder="请输入密码"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        required
      />
      <Button type="submit" loading={submitting}>
        登录
      </Button>
    </form>
  );
}

function RegisterForm() {
  const { doRegister } = useAuth();
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [nickname, setNickname] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [sending, setSending] = useState(false);
  const [countdown, setCountdown] = useState(0);

  // 发送验证码后的倒计时
  useEffect(() => {
    if (countdown <= 0) return;
    const timer = setTimeout(() => setCountdown((c) => c - 1), 1000);
    return () => clearTimeout(timer);
  }, [countdown]);

  const onSendCode = async () => {
    setError(null);
    setNotice(null);
    if (!emailPattern.test(email.trim())) {
      setError("请输入有效的邮箱地址");
      return;
    }
    setSending(true);
    try {
      await sendRegisterCode(email.trim());
      setNotice("验证码已发送,请查收邮箱(开发模式下可在后端日志查看)");
      setCountdown(60);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSending(false);
    }
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await doRegister({
        email: email.trim(),
        code: code.trim(),
        password,
        nickname: nickname.trim(),
      });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form className="auth-form" onSubmit={onSubmit} noValidate>
      {error ? <div className="alert alert-error">{error}</div> : null}
      {notice ? <div className="alert alert-info">{notice}</div> : null}
      <TextField
        label="邮箱"
        name="email"
        type="email"
        autoComplete="email"
        placeholder="you@example.com"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        required
      />
      <div className="field-row">
        <TextField
          label="验证码"
          name="code"
          inputMode="numeric"
          maxLength={6}
          mono
          placeholder="6 位数字"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          required
        />
        <Button
          type="button"
          variant="ghost"
          className="send-code-btn"
          onClick={onSendCode}
          loading={sending}
          disabled={countdown > 0}
        >
          {countdown > 0 ? `${countdown}s 后重发` : "发送验证码"}
        </Button>
      </div>
      <TextField
        label="昵称"
        name="nickname"
        maxLength={32}
        placeholder="给自己起个名字"
        value={nickname}
        onChange={(e) => setNickname(e.target.value)}
        required
      />
      <TextField
        label="密码"
        name="password"
        type="password"
        autoComplete="new-password"
        placeholder="至少 8 位"
        minLength={8}
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        required
      />
      <Button type="submit" loading={submitting}>
        注册并登录
      </Button>
    </form>
  );
}
