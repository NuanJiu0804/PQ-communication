import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 管理后台用 5174,避免与客户端开发服务器(5173)冲突。
export default defineConfig({
  plugins: [react()],
  server: { port: 5174, strictPort: true },
  build: { outDir: "dist", target: "es2021" },
});
