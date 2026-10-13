// 后端 API 基址:开发默认本机后端;可用 VITE_API_BASE_URL 覆盖。
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

// WebSocket 基址(由 API 基址推导)。
export const WS_BASE_URL = API_BASE_URL.replace(/^http/, "ws");
