# 基于后量子混合密码的端到端加密即时通讯系统

端到端加密(E2EE)的即时通讯系统。功能对标微信常规能力,密码学对标 Signal 并做**后量子混合加固**(抵抗「先存后解 / Harvest-Now-Decrypt-Later」)。

> **核心安全不变量:服务器与管理员永远无法获得消息明文与用户私钥,只接触密文与元数据。**
> 私钥生成、消息加解密、本地历史落盘全部在客户端完成;后端只做认证、公钥分发、密文中继/暂存、媒体签发与元数据统计。管理后台据此成为一份「服务器读不到内容」的**隐私证明**(只展示元数据与不可读的密文样本)。

- 客户端:**Tauri**(Rust 安全核心 + React/TypeScript UI),加解密与本地加密存储均在 Rust 核心内完成,密钥与明文不进入 JS 层
- 后端:**Go**(Gin + WebSocket),无状态业务 + PostgreSQL/Redis/MinIO
- 密码学:**纯 Rust 的 RustCrypto**(ML-KEM-768 / ML-DSA-65 / X25519 / Ed25519 / XChaCha20-Poly1305 / HKDF),无需 C 工具链,Windows/Ubuntu 行为一致
- 传输层:可选 **混合后量子 TLS 1.3**(X25519 ‖ ML-KEM-768)

详见 [docs/architecture.md](docs/architecture.md) 与 [docs/design-spec.md](docs/design-spec.md)。

---

## 密码学设计要点

| 环节 | 方案 | 说明 |
|---|---|---|
| 初始密钥协商 | **混合 PQXDH** | X25519 ×(3~4)DH ‖ ML-KEM-768 封装 → HKDF 派生根密钥。经典与后量子任一被攻破都不泄露会话密钥 |
| 会话棘轮 | **双棘轮(Double Ratchet)** | DH 棘轮 + HMAC/HKDF 对称键链 + 跳过密钥缓存,前向保密 + 后向恢复;解密失败不改变状态(抗伪造消息) |
| 会话管理 | **多会话 + 事务性握手** | 每个对端保留当前/归档会话,同时发起或对端重装后自动收敛;握手重放检测;对端身份变化时提醒重新核对安全号码 |
| 消息加密 | **XChaCha20-Poly1305** | 每条消息一次性消息密钥 + AEAD |
| 身份/预密钥签名 | **Ed25519 ‖ ML-DSA-65 混合签名** | 预密钥包双签名,任一算法被攻破签名仍有效 |
| 身份核对 | **安全号码(Safety Number)** | 双方当面/可信渠道比对,防中间人 |
| 本地存储 | **SQLCipher 同级方案** | bundled SQLite + 应用层 XChaCha20-Poly1305,密钥由登录口令经 **Argon2id** 派生 |
| 媒体 | **客户端加密 + 对象存储** | 一次性密钥加密 → MinIO 存密文;密钥随 E2EE 消息端到端传递,服务器只见密文 |
| 账号鉴权 | **Argon2id + JWT + 刷新令牌轮换** | 与 E2EE 密钥体系**完全独立**的两套系统 |
| 传输层(可选) | **TLS 1.3 + X25519MLKEM768** | 握手层再加一道后量子防线,与应用层 E2EE 叠加生效 |

> 选用 RustCrypto 纯 Rust 实现(`ml-kem` = FIPS 203 ML-KEM-768,`ml-dsa` = FIPS 204 ML-DSA-65)而非 liboqs,免去 CMake/OpenSSL 等 C 依赖,跨平台一致。后量子原语集中封装在 `crypto-core/src/pqc.rs` 一层,便于将来整体替换。

---

## 仓库结构

```
tang/
├─ apps/
│  ├─ server/                  Go 后端
│  │  ├─ cmd/server/           服务入口(HTTP/HTTPS、优雅关闭)
│  │  ├─ cmd/initdb/           首次建库(本机原生 PG 用)
│  │  ├─ cmd/gencert/          生成本地自签 TLS 证书(纯标准库)
│  │  ├─ internal/             config/auth/keys/messaging/social/groups/media/admin…
│  │  ├─ migrations/           SQL 迁移(随二进制内嵌,启动自动执行)
│  │  └─ Dockerfile
│  ├─ client/                  Tauri 桌面客户端
│  │  ├─ crypto-core/          纯 Rust 密码学核心库(PQXDH/双棘轮/AEAD/本地存储)
│  │  ├─ src-tauri/            Tauri Rust 外壳 + 命令绑定
│  │  └─ src/                  React/TS 界面
│  └─ admin/                   管理后台(独立 React SPA + Dockerfile/nginx)
├─ scripts/                    Node 端到端集成测试(run-all.mjs 总入口)
├─ docs/                       架构与设计规范
├─ docker-compose.yml          基础设施 + 后端 + 管理后台 一键编排
├─ .env.example               环境配置示例
└─ README.md
```

---

## 当前进度

按「可运行的纵向切片」分阶段交付,**P1 ~ P8 全部完成并通过验证**:

| 阶段 | 内容 | 验证 |
|---|---|---|
| P1 | 邮箱注册/登录、Argon2id、JWT + 刷新令牌轮换、验证码(只存哈希/限频/防爆破)、SMTP | 单元测试 + 浏览器实测全流程 |
| P2 | 混合 PQXDH + 双棘轮 + 混合签名 + 安全号码;预密钥分发 + WebSocket 密文中继(在线/离线) | `cargo test` 38 项 + `test-p2b` |
| P3 | 送达/已读回执、未读、撤回、在线/正在输入;**SQLCipher 同级本地加密存储** | `test-p3` |
| P4 | 好友申请/同意/拒绝/删除、黑名单、资料、搜索 | `test-p4` |
| P5 | 群聊(成对扇出加密)+ 媒体收发(客户端加密 → MinIO 密文) | `test-p56` + 客户端构建 |
| P6 | 管理后台(元数据统计 / 隐私证明 / 封禁 / 审计) | `test-p56` + 浏览器实测 |
| P7 | 混合后量子 TLS、Docker 编排、集成测试总入口、双平台说明、本文档 | `run-all` 全绿 + openssl 实测 PQ 握手 |
| P8 | 安全加固(见下方「安全加固记录」) | `cargo test` + `test-security` |

集成测试(`scripts/run-all.mjs`)针对**真实** PostgreSQL/Redis/MinIO/WebSocket 一次性全绿。

---

## 先决条件

| 工具 | 用途 | Windows(winget) | Ubuntu |
|---|---|---|---|
| Go ≥ 1.25 | 编译/运行后端 | `winget install GoLang.Go` | 官方 tar 或 `snap install go --classic` |
| Node ≥ 20 | 客户端/管理后台前端、集成测试 | `winget install OpenJS.NodeJS` | NodeSource apt |
| Rust(rustup)| Tauri 客户端核心 | `winget install Rustlang.Rustup` | `curl https://sh.rustup.rs -sSf \| sh` |
| Docker(可选)| 一键拉起全栈 | `winget install Docker.DockerDesktop` | [官方 apt 源](https://docs.docker.com/engine/install/ubuntu/) |
| PostgreSQL / Redis / MinIO | 数据存储(非 Docker 时本机原生安装) | 见下方「本机原生开发」 | apt / 官方二进制 |

> Windows 下编译 Tauri 客户端还需:**WebView2 运行时**(Win11 一般已内置)、**Visual Studio C++ 生成工具**(crypto-core 的 bundled SQLite 需要 C 编译器)。

---

## 快速开始

### 0. 准备环境变量

```bash
# Windows PowerShell
Copy-Item .env.example .env
# Linux / macOS
cp .env.example .env
```

至少确认/修改:`POSTGRES_PASSWORD`、`MINIO_ROOT_USER`、`MINIO_ROOT_PASSWORD`、`JWT_SECRET`、`ADMIN_PASSWORD`。

### 方式 A:Docker 一键(后端 + 管理后台 + 基础设施)

> 适合**服务器部署 / Ubuntu**。客户端是桌面应用,不在容器内(见下文)。

```bash
docker compose up -d --build
```

依次拉起 postgres、redis、minio、minio-init(建 bucket)、server(自动迁移数据库)、admin(nginx 静态站,把 `/api/` 反代到 server)。默认端口:

- 后端 API:<http://localhost:8080>
- 管理后台:<http://localhost:5174>(`ADMIN_USERNAME` / `ADMIN_PASSWORD` 登录)
- MinIO 控制台:<http://localhost:9001>

只拉基础设施(本机 `go run` 后端时用):

```bash
docker compose up -d postgres redis minio minio-init
```

### 方式 B:本机原生开发(无 Docker,推荐 Windows 开发)

**基础设施**(均按 `.env` 的 localhost 端口运行):

- PostgreSQL:本机安装,启动监听 5432。
- Redis:Windows 可用 [Memurai](https://www.memurai.com/) 或 [tporadowski/redis](https://github.com/tporadowski/redis/releases),监听 6379。
- MinIO:单文件运行(密钥与 `.env` 一致):
  ```powershell
  $env:MINIO_ROOT_USER='pqchat'; $env:MINIO_ROOT_PASSWORD='pqchat_dev_password'
  C:\minio\minio.exe server C:\minio\data --console-address ":9001"
  ```

**运行后端:**

```bash
cd apps/server
go mod tidy

# 首次:创建应用数据库(本机原生 PG 不会自动建库;compose 的 PG 会按 POSTGRES_DB 自动建,可跳过)
go run ./cmd/initdb

# 启动后端(自动连依赖、执行迁移、监听 :8080)
go run ./cmd/server
```

> Windows 若 `go` 不在 PATH:`& 'C:\Program Files\Go\bin\go.exe' run ./cmd/server`。

健康检查:

```bash
curl http://localhost:8080/healthz   # 存活,恒 200
curl http://localhost:8080/readyz    # 就绪,PG/Redis/MinIO 全 up 才 200
```

---

## 桌面客户端(Tauri)

加解密在桌面端的 Rust 核心完成,**浏览器预览不支持聊天**(会提示需用桌面应用);前端界面本身可在浏览器单独预览。

```bash
cd apps/client
npm install

# 仅前端预览(浏览器,无需 Rust)—— 登录/注册等界面
npm run dev            # http://localhost:5173

# 完整桌面应用(需先装 Rust)
npm run icons          # 首次:生成应用图标集
npm run tauri dev      # 启动桌面窗口
```

`npm run build` 做 `tsc` 类型检查 + Vite 打包;`npm run tauri build` 产出安装包。

### 体验端到端加密(单聊 / 群聊 / 媒体)

1. 确保后端与基础设施(尤其 **MinIO**,媒体收发需要)在运行。
2. 起两个桌面实例(`apps/client` 下开两个终端各跑 `npm run tauri dev`,或装好后开两份)。
3. 两端各注册/登录不同账号,在「我的 ID」复制各自用户 ID。
4. 一方在「发起会话」粘贴对方 ID 即可端到端加密互发文本/图片/文件;会话头点盾牌核对**安全号码**(双方应一致)。
5. 群聊在「群组」标签新建并选好友;群消息按成员**成对扇出**逐一加密。

> 服务端只中继密文:消息在 `message_envelopes` 表里是不可读的 `ciphertext`;管理后台以此作为隐私证明。

---

## 后量子 TLS(可选,传输层加固)

在应用层 E2EE 之外,后端可再启用**混合后量子 TLS 1.3**,使握手层也抵抗「先存后解」。

```bash
# 1) 生成本地自签证书(纯标准库,无需 OpenSSL;覆盖 localhost/127.0.0.1/::1)
cd apps/server
go run ./cmd/gencert            # 生成 certs/dev-cert.pem 与 certs/dev-key.pem

# 2) 在 .env 启用
#    TLS_ENABLED=true
#    TLS_CERT_FILE=certs/dev-cert.pem
#    TLS_KEY_FILE=certs/dev-key.pem

# 3) 启动后端,日志会显示 “HTTPS 服务已监听(TLS 1.3 + 混合后量子 X25519MLKEM768)”
go run ./cmd/server
```

**验证协商到的是后量子密钥交换组**(需 OpenSSL ≥ 3.2):

```bash
echo Q | openssl s_client -connect 127.0.0.1:8080 -tls1_3
# 期望输出:
#   Negotiated TLS1.3 group: X25519MLKEM768
#   Protocol: TLSv1.3
```

> 实现见 [internal/api/server.go](apps/server/internal/api/server.go) 的 `pqTLSConfig`:强制 TLS 1.3,`CurvePreferences` 把 `X25519MLKEM768` 排在 `X25519` 之前。证书签名算法(Ed25519)与此无关——后量子加固在「密钥交换」环节。生产环境请换用受信任 CA 证书,或由前置反向代理终止 TLS。

---

## 集成测试

针对**真实**后端 + 基础设施(非 mock)的端到端用例,覆盖密钥分发、密文中继(在线/离线)、回执/撤回/在线状态、好友、群组、媒体密文往返、管理后台隐私证明等 60+ 断言。

```bash
# 前置:后端 + PG/Redis/MinIO 已运行;后端日志写入文件(未配置 SMTP 的开发模式会把验证码打到日志)。
# 例如以日志重定向方式启动后端:  go run ./cmd/server > server.log 2>&1

node scripts/run-all.mjs <后端日志路径> [base]
# 示例:
node scripts/run-all.mjs apps/server/server.log http://localhost:8080
```

`run-all.mjs` 依次运行五套用例并汇总;也可单独运行某一套(参数同为 `<日志路径> [base]`):

```bash
node scripts/test-p2b.mjs  apps/server/server.log   # 密钥分发 + WS 中继
node scripts/test-p3.mjs   apps/server/server.log   # 回执/撤回/在线/输入
node scripts/test-p4.mjs   apps/server/server.log   # 好友/黑名单
node scripts/test-p56.mjs  apps/server/server.log   # 群组/媒体/管理后台
node scripts/test-security.mjs apps/server/server.log # 安全加固回归(越权/黑名单/令牌竞态/封禁等)
```

> 若 `.env` 配置了真实 SMTP,验证码会发到邮箱而不会写入日志,集成测试将取不到验证码。
> 运行测试时可临时清空 SMTP:PowerShell 中 `$env:SMTP_HOST=''; go run ./cmd/server > server.log 2>&1`。

客户端密码学核心另有 Rust 单元/集成测试:`cd apps/client/crypto-core && cargo test`。

---

## 管理后台(隐私证明)

独立 React SPA(`apps/admin`,开发端口 5174;容器内 nginx 提供并反代 `/api/`)。用 `.env` 的 `ADMIN_USERNAME` / `ADMIN_PASSWORD` 登录(后端启动时若该用户不存在则按此播种 superadmin)。

```bash
cd apps/admin
npm install
npm run dev      # http://localhost:5174
```

四个视图:**概览**(用户/在线/群组/消息统计)、**转发消息**(隐私证明横幅 + 密文样本表,无任何明文字段)、**用户管理**(封禁/解封)、**审计日志**。管理后台使用独立的 admin JWT(`typ=admin`),普通用户令牌访问管理接口返回 401。

---

## 双平台说明(Windows 开发 / Ubuntu 部署)

- **代码跨平台**:Go 后端 `CGO_ENABLED=0` 纯静态;crypto-core 纯 Rust;前端与 Node 测试平台无关。所有路径/换行/随机数走标准库,Windows 与 Ubuntu 行为一致。
- **开发(Windows)**:基础设施本机原生安装(见方式 B),`go run` + `npm run tauri dev` 调试。
- **部署(Ubuntu)**:`docker compose up -d --build` 一键拉起后端 + 管理后台 + 基础设施;桌面客户端用 `npm run tauri build` 在目标平台分别打包(Tauri 不交叉打包桌面安装包)。
- **证书**:开发用 `go run ./cmd/gencert` 自签;生产用受信任 CA 证书并设置 `TLS_*`,或由 Nginx/Caddy 等前置反代终止 TLS。

---

## 安全说明

- 所有敏感配置走 `.env`,**严禁硬编码**;`.env`、`certs/`、`*.pem` 均已被 `.gitignore` 忽略。
- 后端**不持有任何用户私钥,不存储任何消息明文**;E2EE 全程在客户端完成。
- 账号鉴权(JWT/刷新令牌)与 E2EE 密钥体系是两套独立系统;验证码只存哈希、限频、防爆破;刷新令牌轮换吊销。
- 生产部署前务必替换:`JWT_SECRET`(≥ 32 字节随机,生产环境过短会拒绝启动)、`POSTGRES_PASSWORD`、`MINIO_ROOT_PASSWORD`、`ADMIN_PASSWORD`,并启用 TLS。
- 源码中形如 `PQChat-...-v1` 的字节串是协议域分隔常量(早期项目代号),不是展示名称;修改会使已有会话与本地加密数据失效,故保持不变。同理,应用标识 `com.pqchat.desktop`(决定本地数据目录)也保持不变。

---

## 安全加固记录(P8)

对全部代码做了一轮审查,修复的问题如下(均有对应的单元测试或集成测试):

**客户端密码学核心(crypto-core)**

| 问题 | 影响 | 修复 |
|---|---|---|
| 双棘轮解密先推进状态、后校验 AEAD | 攻击者(或恶意服务器)发一条带新 DH 公钥的伪造消息即可让接收方棘轮错位,会话永久失效 | 解密改为事务性:在副本上推进,校验通过才提交 |
| 握手先消费一次性预密钥、替换会话,再解密首条 | 篡改的首条消息会白白消耗预密钥并覆盖原会话 | 握手同样事务化:首条解密成功才提交 |
| 无一次性预密钥时可重放首条握手 | 重放即可把对方会话重置回初始状态 | 记录已处理握手的临时公钥,拒绝重放 |
| 双方同时发起会话时,后到的一方会话错配 | 双方都无法解密对方消息 | 每个对端保留当前 + 归档会话,解密成功的会话自动提升为当前 |
| 只有首条消息携带握手头 | 首条丢失则会话永远无法建立 | 对端回复前每条消息都携带握手头 |
| 对端重置/重装后,本端无提示 | 安全号码已变却无人知晓(中间人检测失效) | 检测身份变化并在会话中提示重新核对安全号码 |
| 未校验握手声明的预密钥编号;多处 `expect` | 畸形输入导致错误密钥或进程 panic | 校验编号;所有可由外部输入触发的 panic 改为错误返回 |
| 一次性预密钥用完后从不补充 | 后续会话失去一次性预密钥带来的额外前向保密 | 登录及收到新握手后按水位自动补充(编号单调递增不复用) |
| 落盘格式无版本 | 升级后旧数据无法加载 | 引入版本标记,旧格式自动迁移 |

**后端**

| 问题 | 影响 | 修复 |
|---|---|---|
| 已读回执不校验身份,且发往客户端指定的 `to` | 任何人可伪造他人消息的已读状态、向任意用户推送回执 | 仅接收方可标记已读,回执发给信封真实发送者 |
| 撤回通知发往客户端指定的 `to` | 撤回通知可投给任意第三方,真实接收方却收不到 | 通知发给信封真实接收方 |
| 消息中继不检查黑名单 | 被拉黑者仍可发消息/正在输入/查看在线状态 | 发送、正在输入、在线状态均检查拉黑关系 |
| 不校验 `group_id` | 任何人可冒充群消息,已退群成员仍能被扇出 | 发送方与接收方都必须是该群当前成员 |
| 离线补发队列满时直接丢弃 | 握手消息被丢,后续消息先到导致会话无法建立 | 改为阻塞式按序补发 |
| WebSocket 单帧默认 32 KB 上限 | 长消息直接导致连接被断开 | 显式设置帧上限,并对密文大小做业务校验 |
| 身份重置后旧一次性预密钥仍在服务器 | 他人领到旧公钥,与重置后的用户永远无法建立会话 | 身份变更时作废旧的一次性预密钥 |
| 上传公钥不校验长度;可领取自己的预密钥包 | 畸形数据进入分发;白白消耗预密钥 | 校验各密钥/签名长度;禁止领取自己的 |
| 同一刷新令牌并发刷新可成功多次 | 一个令牌换出多个有效令牌 | 以 `revoked_at IS NULL` 条件原子轮换 |
| 封禁不影响已登录会话 | 被封禁用户在线连接与刷新令牌继续有效 | 封禁时踢下线、吊销刷新令牌,WebSocket 接入时检查封禁 |
| 管理员登录无限速 | 管理员口令可被暴力破解 | 按用户名/IP 失败次数限速并写审计 |
| 邮箱不存在时登录立即返回 | 可通过响应时间枚举注册邮箱 | 不存在时也执行一次 Argon2id |
| 非法 UUID 参数导致 500 | 错误信息与日志噪声 | 统一校验路径参数,返回 404 |
| 媒体大小/对象键未校验 | 可申请超大上传、为任意对象键签发下载链接 | 限制 25 MB,对象键须为服务器生成格式 |

**客户端界面**

| 问题 | 修复 |
|---|---|
| WebSocket 重连沿用登录时的访问令牌(15 分钟后过期),重连永远失败 | 每次重连前刷新令牌;指数退避;登出后不再「僵尸重连」 |
| 重复投递的消息被再次解密并报错 | 按服务端信封 ID 去重 |
| 解密失败的消息被静默丢弃 | 显示提示;若是本机丢失会话则自动重新协商 |
| 撤回通知可撤回任意会话中的任意消息 | 只撤回「该发送者发给我」的消息,并清除媒体密钥 |
| 群消息使用缓存的成员列表 | 每次发送取最新成员 |
| 首次上传公钥失败后永不重传 | 每次登录幂等同步公钥 |
| 非网络错误也显示「无法连接服务器」 | 区分网络错误、业务错误与本地密码学错误 |
```
