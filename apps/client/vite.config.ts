import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri 开发服务器使用固定端口 5173;构建产物输出到 dist 供 Tauri 打包。
export default defineConfig({
  plugins: [react()],
  // Tauri 自身会清屏,这里关闭 Vite 清屏以保留两边日志
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    target: "es2021",
    sourcemap: true,
  },
});
