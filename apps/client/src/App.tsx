import { useEffect, useState } from "react";
import { ShieldCheck, Moon, Sun, Loader2 } from "lucide-react";

import { AuthProvider, useAuth } from "./auth/AuthContext";
import { ChatProvider } from "./chat/ChatContext";
import { AuthScreen } from "./screens/AuthScreen";
import { MainScreen } from "./screens/MainScreen";

type Theme = "light" | "dark";

export default function App() {
  return (
    <AuthProvider>
      <Shell />
    </AuthProvider>
  );
}

function Shell() {
  const { status } = useAuth();
  const [theme, setTheme] = useState<Theme>("light");
  const [version, setVersion] = useState<string>("—");
  const [runtime, setRuntime] = useState<"desktop" | "web">("web");

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  useEffect(() => {
    const isTauri = "__TAURI_INTERNALS__" in window;
    if (!isTauri) return;
    setRuntime("desktop");
    import("@tauri-apps/api/core")
      .then(({ invoke }) => invoke<string>("app_version"))
      .then((v) => setVersion(v))
      .catch(() => setVersion("未知"));
  }, []);

  const toggleTheme = () => setTheme((t) => (t === "light" ? "dark" : "light"));

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <ShieldCheck className="brand-mark" size={20} aria-hidden />
          <span className="brand-name">基于后量子混合密码的端到端加密即时通讯系统</span>
        </div>
        <button
          className="icon-button"
          onClick={toggleTheme}
          aria-label={theme === "light" ? "切换到深色模式" : "切换到浅色模式"}
          title={theme === "light" ? "深色模式" : "浅色模式"}
        >
          {theme === "light" ? <Moon size={18} aria-hidden /> : <Sun size={18} aria-hidden />}
        </button>
      </header>

      <main className={status === "authenticated" ? "app-main app-main--full" : "app-main"}>
        {status === "loading" ? (
          <div className="loading">
            <Loader2 className="spin" size={22} aria-hidden />
            <span>正在恢复会话…</span>
          </div>
        ) : status === "authenticated" ? (
          <ChatProvider>
            <MainScreen />
          </ChatProvider>
        ) : (
          <AuthScreen />
        )}
      </main>

      <footer className="app-footer">
        <span className="mono">client v{version}</span>
        <span className="dot" aria-hidden>
          ·
        </span>
        <span className="mono">{runtime === "desktop" ? "desktop (tauri)" : "web 预览"}</span>
      </footer>
    </div>
  );
}
