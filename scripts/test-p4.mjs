// P4 测试:好友申请/同意/拒绝/删除、黑名单、资料、搜索。
// 用法:node scripts/test-p4.mjs <server-log-path> [base]
import { readFileSync } from "node:fs";

const LOG = process.argv[2];
const BASE = process.argv[3] || "http://localhost:8080";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
  const email = `p4_${tag}_${Date.now()}_${Math.floor(Math.random() * 1e6)}@example.com`;
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

async function main() {
  const alice = await setupUser("alice");
  const bob = await setupUser("bob");
  const carol = await setupUser("carol");

  console.log("== 资料更新与读取 ==");
  const upd = await api("/api/v1/me/profile", {
    method: "PATCH",
    token: alice.token,
    body: { nickname: "Alice 改名", status_text: "在线" },
  });
  check("更新资料 200", upd.status === 200 && upd.data.nickname === "Alice 改名");
  const prof = await api(`/api/v1/users/${alice.id}`, { token: bob.token });
  check("他人可读公开资料", prof.status === 200 && prof.data.status_text === "在线");

  console.log("== 按邮箱搜索 ==");
  const search = await api(`/api/v1/search/users?email=${encodeURIComponent(bob.email)}`, { token: alice.token });
  check("搜索到 Bob", search.status === 200 && search.data.id === bob.id);

  console.log("== 好友申请 → 同意 ==");
  const req = await api("/api/v1/friend-requests", {
    method: "POST",
    token: alice.token,
    body: { to_user_id: bob.id, note: "交个朋友" },
  });
  check("发送申请 200 且非自动同意", req.status === 200 && req.data.auto_accepted === false);

  const incoming = await api("/api/v1/friend-requests", { token: bob.token });
  check("Bob 收到一条申请", incoming.data.incoming.length === 1 && incoming.data.incoming[0].user.id === alice.id);
  const reqId = incoming.data.incoming[0].id;

  const acc = await api(`/api/v1/friend-requests/${reqId}/accept`, { method: "POST", token: bob.token });
  check("同意申请 200", acc.status === 200);

  const aliceFriends = await api("/api/v1/friends", { token: alice.token });
  const bobFriends = await api("/api/v1/friends", { token: bob.token });
  check("Alice 好友含 Bob", aliceFriends.data.friends.some((f) => f.id === bob.id));
  check("Bob 好友含 Alice", bobFriends.data.friends.some((f) => f.id === alice.id));

  console.log("== 反向申请自动互加 ==");
  await api("/api/v1/friend-requests", { method: "POST", token: bob.token, body: { to_user_id: carol.id, note: "" } });
  const auto = await api("/api/v1/friend-requests", { method: "POST", token: carol.token, body: { to_user_id: bob.id, note: "" } });
  check("反向申请自动同意", auto.status === 200 && auto.data.auto_accepted === true);
  const carolFriends = await api("/api/v1/friends", { token: carol.token });
  check("Carol 好友含 Bob", carolFriends.data.friends.some((f) => f.id === bob.id));

  console.log("== 删除好友 ==");
  await api(`/api/v1/friends/${bob.id}`, { method: "DELETE", token: alice.token });
  const af2 = await api("/api/v1/friends", { token: alice.token });
  const bf2 = await api("/api/v1/friends", { token: bob.token });
  check("删除后 Alice 好友不含 Bob", !af2.data.friends.some((f) => f.id === bob.id));
  check("删除后 Bob 好友不含 Alice", !bf2.data.friends.some((f) => f.id === alice.id));

  console.log("== 黑名单 ==");
  await api(`/api/v1/blocks/${carol.id}`, { method: "POST", token: alice.token });
  const blocks = await api("/api/v1/blocks", { token: alice.token });
  check("黑名单含 Carol", blocks.data.blocks.some((b) => b.id === carol.id));
  const blockedReq = await api("/api/v1/friend-requests", {
    method: "POST",
    token: alice.token,
    body: { to_user_id: carol.id },
  });
  check("向黑名单用户发申请被拒(403)", blockedReq.status === 403);
  await api(`/api/v1/blocks/${carol.id}`, { method: "DELETE", token: alice.token });
  const blocks2 = await api("/api/v1/blocks", { token: alice.token });
  check("取消拉黑后黑名单为空", !blocks2.data.blocks.some((b) => b.id === carol.id));

  console.log("== 拒绝申请 ==");
  await api("/api/v1/friend-requests", { method: "POST", token: bob.token, body: { to_user_id: alice.id } });
  const inc2 = await api("/api/v1/friend-requests", { token: alice.token });
  const rid = inc2.data.incoming[0].id;
  const rej = await api(`/api/v1/friend-requests/${rid}/reject`, { method: "POST", token: alice.token });
  check("拒绝申请 200", rej.status === 200);
  const af3 = await api("/api/v1/friends", { token: alice.token });
  check("拒绝后未成为好友", !af3.data.friends.some((f) => f.id === bob.id));

  console.log(failures === 0 ? "\n全部通过 ✅" : `\n有 ${failures} 项失败 ❌`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("测试异常:", e.message);
  process.exit(1);
});
