// P5/P6 测试:群组、媒体(MinIO 预签名密文往返)、管理后台(元数据/隐私证明/封禁/审计)。
// 用法:node scripts/test-p56.mjs <server-log-path> [base]
import { readFileSync } from "node:fs";

const LOG = process.argv[2];
const BASE = process.argv[3] || "http://localhost:8080";
const WSURL = BASE.replace(/^http/, "ws") + "/api/v1/ws";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const enc = (s) => Buffer.from(s).toString("base64");

let failures = 0;
function check(name, cond) {
  console.log(`${cond ? "  OK " : " FAIL"}  ${name}`);
  if (!cond) failures++;
}

async function api(path, { method = "GET", token, body } = {}) {
  const headers = {};
  if (body) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${BASE}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  return { status: res.status, data: text ? JSON.parse(text) : null };
}

function codeFromLog(email) {
  let code = null;
  for (const ln of readFileSync(LOG, "utf8").split(/\r?\n/)) {
    if (ln.includes(email)) {
      const m = ln.match(/"code":"(\d{6})"/);
      if (m) code = m[1];
    }
  }
  return code;
}

async function setupUser(tag) {
  const email = `p56_${tag}_${Date.now()}_${Math.floor(Math.random() * 1e6)}@example.com`;
  await api("/api/v1/auth/register/send-code", { method: "POST", body: { email } });
  await sleep(400);
  const code = codeFromLog(email);
  const r = await api("/api/v1/auth/register", {
    method: "POST",
    body: { email, code, password: "SuperSecret123", nickname: tag },
  });
  if (r.status !== 201) throw new Error(`注册 ${tag} 失败: ${r.status}`);
  return { token: r.data.access_token, id: r.data.user.id, email };
}

function connectWS(token) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${WSURL}?token=${encodeURIComponent(token)}`);
    const buf = [];
    const waiters = [];
    ws.addEventListener("message", (ev) => {
      const m = JSON.parse(ev.data);
      buf.push(m);
      for (let i = waiters.length - 1; i >= 0; i--) {
        if (waiters[i].pred(m)) {
          waiters[i].resolve(m);
          waiters.splice(i, 1);
        }
      }
    });
    ws.waitFor = (pred, timeout = 5000) =>
      new Promise((res, rej) => {
        const found = buf.find(pred);
        if (found) return res(found);
        const w = { pred, resolve: res };
        waiters.push(w);
        setTimeout(() => rej(new Error("等待消息超时")), timeout);
      });
    ws.sendJSON = (o) => ws.send(JSON.stringify(o));
    ws.onopen = () => resolve(ws);
    ws.onerror = (e) => reject(new Error("WS 错误"));
  });
}

async function main() {
  const alice = await setupUser("alice");
  const bob = await setupUser("bob");
  const carol = await setupUser("carol");

  console.log("== 群组 ==");
  const create = await api("/api/v1/groups", {
    method: "POST",
    token: alice.token,
    body: { name: "测试群", member_ids: [bob.id, carol.id] },
  });
  check("建群 201,成员 3", create.status === 201 && create.data.member_count === 3);
  const gid = create.data.id;

  const myGroups = await api("/api/v1/groups", { token: bob.token });
  check("Bob 的群列表含该群", myGroups.data.groups.some((g) => g.id === gid));

  const detail = await api(`/api/v1/groups/${gid}`, { token: alice.token });
  check("群详情含 3 名成员且群主为 Alice", detail.data.members.length === 3 && detail.data.owner_id === alice.id);

  console.log("== 群消息中继(带 group_id)==");
  const bobWs = await connectWS(bob.token);
  const aliceWs = await connectWS(alice.token);
  aliceWs.sendJSON({ type: "send", to: bob.id, group_id: gid, envelope_type: "message", payload: enc("群消息密文") });
  const gmsg = await bobWs.waitFor((m) => m.type === "message" && m.group_id === gid);
  check("Bob 收到带 group_id 的群消息", gmsg.from === alice.id && gmsg.group_id === gid);

  console.log("== 群成员增减 ==");
  const dave = await setupUser("dave");
  await api(`/api/v1/groups/${gid}/members`, { method: "POST", token: alice.token, body: { user_id: dave.id } });
  const d2 = await api(`/api/v1/groups/${gid}`, { token: alice.token });
  check("加人后成员 4", d2.data.member_count === 4);

  await api(`/api/v1/groups/${gid}/leave`, { method: "POST", token: bob.token });
  const bg = await api("/api/v1/groups", { token: bob.token });
  check("Bob 退群后其群列表不含该群", !bg.data.groups.some((g) => g.id === gid));

  await api(`/api/v1/groups/${gid}/members/${carol.id}`, { method: "DELETE", token: alice.token });
  const d3 = await api(`/api/v1/groups/${gid}`, { token: alice.token });
  check("群主移除 Carol 后不含 Carol", !d3.data.members.some((m) => m.id === carol.id));

  console.log("== 媒体(MinIO 预签名密文往返)==");
  const cipher = Buffer.from("假装这是客户端加密后的媒体密文-" + Date.now());
  const up = await api("/api/v1/media/upload-url", {
    method: "POST",
    token: alice.token,
    body: { content_type: "application/octet-stream", size: cipher.length },
  });
  check("获取上传 URL", up.status === 200 && !!up.data.upload_url && !!up.data.object_key);
  const put = await fetch(up.data.upload_url, { method: "PUT", body: cipher });
  check("PUT 密文到 MinIO", put.ok);
  const dl = await api(`/api/v1/media/download-url?key=${encodeURIComponent(up.data.object_key)}`, { token: bob.token });
  check("获取下载 URL", dl.status === 200 && !!dl.data.download_url);
  const get = await fetch(dl.data.download_url);
  const got = Buffer.from(await get.arrayBuffer());
  check("下载密文与上传一致", Buffer.compare(got, cipher) === 0);

  console.log("== 管理后台 ==");
  const adminUser = process.env.ADMIN_USERNAME || "admin";
  const adminPass = process.env.ADMIN_PASSWORD || "admin123456";
  const alogin = await api("/api/v1/admin/login", { method: "POST", body: { username: adminUser, password: adminPass } });
  check("管理员登录,角色 superadmin", alogin.status === 200 && alogin.data.role === "superadmin");
  const at = alogin.data.access_token;

  const stats = await api("/api/v1/admin/stats", { token: at });
  check("stats 注册用户 > 0", stats.data.registered_users > 0);
  check("stats 含群组数 ≥ 1", stats.data.groups >= 1);

  const msgs = await api("/api/v1/admin/messages?limit=20", { token: at });
  const m0 = msgs.data.messages[0];
  check("有转发消息元数据", msgs.data.messages.length > 0);
  check("含密文样本(base64)", m0 && typeof m0.ciphertext_sample === "string" && m0.ciphertext_sample.length > 0);
  check("隐私证明:无任何明文字段", m0 && !("plaintext" in m0) && !("content" in m0) && !("text" in m0));

  const users = await api("/api/v1/admin/users", { token: at });
  check("用户列表含 Alice", users.data.users.some((u) => u.id === alice.id));

  await api(`/api/v1/admin/users/${alice.id}/ban`, { method: "POST", token: at });
  const banned = await api("/api/v1/auth/login", { method: "POST", body: { email: alice.email, password: "SuperSecret123" } });
  check("封禁后 Alice 登录被拒(403)", banned.status === 403);
  await api(`/api/v1/admin/users/${alice.id}/unban`, { method: "POST", token: at });

  const audit = await api("/api/v1/admin/audit", { token: at });
  check("审计日志非空(含登录/封禁)", audit.data.audit.length > 0);

  const forbidden = await api("/api/v1/admin/stats", { token: alice.token });
  check("普通用户令牌访问管理接口被拒(401)", forbidden.status === 401);

  console.log(failures === 0 ? "\n全部通过 ✅" : `\n有 ${failures} 项失败 ❌`);
  process.exitCode = failures === 0 ? 0 : 1;
  await closeAll(aliceWs, bobWs);
  // 不强制 process.exit:关闭 WS 后让事件循环自然退出,使 libuv 完成句柄回收,
  // 避免 Windows 上强制退出触发 src\win\async.c 断言。兜底定时器 unref,不阻止自然退出。
  setTimeout(() => process.exit(process.exitCode), 1500).unref();
}

// 等待所有 WebSocket 完成关闭后再返回,避免 Node(Windows)在句柄关闭中
// 强制退出触发 libuv 断言(src\win\async.c)。
function closeAll(...sockets) {
  return Promise.all(
    sockets.map(
      (ws) =>
        new Promise((res) => {
          if (!ws || ws.readyState === 3) return res();
          ws.addEventListener("close", () => res(), { once: true });
          try {
            ws.close();
          } catch {
            res();
          }
          setTimeout(res, 800); // 兜底:最多等 800ms
        }),
    ),
  );
}

main().catch((e) => {
  console.error("测试异常:", e.message);
  process.exit(1);
});
