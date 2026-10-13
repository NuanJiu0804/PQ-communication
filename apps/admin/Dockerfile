# syntax=docker/dockerfile:1

# =============================================================================
# 基于后量子混合密码的端到端加密即时通讯系统 管理后台(静态 SPA)容器镜像
# 多阶段:Node 构建 → nginx 提供静态资源,并把 /api/ 反向代理到后端 server。
#
# 构建参数:
#   VITE_API_BASE_URL  前端 API 基址。默认空串 = 用同源相对路径,
#                      由本镜像内 nginx 把 /api/ 代理到 compose 网络里的 server。
# =============================================================================

# ---- 构建阶段 ----
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
# 同源部署:留空让请求走相对路径,nginx 负责转发到后端
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
RUN npm run build

# ---- 运行阶段 ----
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost/ >/dev/null 2>&1 || exit 1
