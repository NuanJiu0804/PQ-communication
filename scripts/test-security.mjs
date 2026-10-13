// 安全加固回归测试:验证中继/密钥分发/鉴权层面的越权与滥用防护。
// 用法:node scripts/test-security.mjs <server-log-path> [base]
//
// 覆盖:
//  - 已读回执只能由接收方发出,且只送达真实发送者(不可伪造/不可投给第三方)
//  - 撤回通知只送达信封的真实接收方
//  - 被拉黑后无法发消息、正在输入不转发、在线状态不泄露
//  - 伪造 group_id(非群成员)的群消息被拒绝
//  - 非法信封类型 / 非法接收方被拒绝
//  - 公钥长度校验;身份变更后旧一次性预密钥作废;不能领取自己的预密钥包
//  - 同一刷新令牌并发刷新只能成功一次
//  - 被封禁账号无法接入 WebSocket,已有连接被踢下线
//  - 非法 UUID 路径参数返回 404 而非 500
import { readFileSync } from "node:fs";

const LOG = process.argv[2];
const BASE = process.argv[3] || "http://localhost:8080";
const WSURL = BASE.replace(/^http/, "ws") + "/api/v1/ws";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const enc = (s) => Buffer.from(s).toString("base64");
const fill = (n, v = 1) => Buffer.alloc(n, v).toString("base64");

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
  const email = `sec_${tag}_${Date.now()}_${Math.floor(Math.random() * 1e6)}@example.com`;
  await api("/api/v1/auth/register/send-code", { method: "POST", body: { email } });
  await sleep(400);
  const code = codeFromLog(email);
  const r = await api("/api/v1/auth/register", {
    method: "POST",
    body: { email, code, password: "SuperSecret123", nickname: tag },
  });
  if (r.status !== 201) throw new Error(`注册 ${tag} 失败: ${r.status}`);
  return { token: r.data.access_token, refresh: r.data.refresh_token, id: r.data.user.id, email };
}

function keys(identityByte, otpkIds) {
  return {
    identity: { ik_ed: fill(32, identityByte), ik_x: fill(32, identityByte), ik_mldsa: fill(1952, identityByte) },
    signed_prekey: { id: 1, public: fill(32), sig_ed: fill(64), sig_mldsa: fill(3309) },
    pq_prekey: { id: 1, public_ek: fill(1184), sig_ed: fill(64), sig_mldsa: fill(3309) },
    one_time_prekeys: otpkIds.map((id) => ({ id, public: fill(32, identityByte) })),
  };
}

function connectWS(token) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${WSURL}?token=${encodeURIComponent(token)}`);
    const buf = [];
    const waiters = [];
    ws.closed = false;
    ws.addEventListener("close", () => (ws.closed = true));
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
        setTimeout(() => {
          const idx = waiters.indexOf(w);
          if (idx >= 0) waiters.splice(idx, 1);
          rej(new Error("等待消息超时"));
        }, timeout);
      });
    // 断言「一段时间内不会收到」某类消息
    ws.never = async (pred, ms = 800) => {
      await sleep(ms);
      return !buf.some(pred);
    };
    ws.sendJSON = (obj) => ws.send(JSON.stringify(obj));
    ws.onopen = () => resolve(ws);
    ws.onerror = () => reject(new Error("WS 连接失败"));
  });
}

async function send(ws, ref, to, extra = {}) {
  ws.sendJSON({ type: "send", client_ref: ref, to, envelope_type: "message", payload: enc(ref), ...extra });
  return ws.waitFor((m) => m.type === "ack" && m.client_ref === ref);
}

async function main() {
  const alice = await setupUser("alice");
  const bob = await setupUser("bob");
  const eve = await setupUser("eve");
  const aliceWs = await connectWS(alice.token);
  const bobWs = await connectWS(bob.token);
  const eveWs = await connectWS(eve.token);

  console.log("== 已读回执授权 ==");
  const ack = await send(aliceWs, "m1", bob.id);
  check("Alice → Bob 已送达", ack.status === "delivered");
  // Eve 不是接收方,伪造已读并试图投给 Alice
  eveWs.sendJSON({ type: "receipt", to: alice.id, message_id: ack.id, status: "read" });
  check("非接收方伪造的已读回执不会送达", await aliceWs.never((m) => m.type === "receipt" && m.status === "read"));
  // Bob 是接收方,但把 to 指向 Eve:回执应发给真实发送者 Alice,而不是 Eve
  bobWs.sendJSON({ type: "receipt", to: eve.id, message_id: ack.id, status: "read" });
  const rr = await aliceWs.waitFor((m) => m.type === "receipt" && m.status === "read" && m.message_id === ack.id);
  check("接收方的已读回执送达真实发送者", rr.from === bob.id);
  check("回执不会投给客户端指定的第三方", await eveWs.never((m) => m.type === "receipt"));

  console.log("== 撤回通知只送达真实接收方 ==");
  const ack2 = await send(aliceWs, "m2", bob.id);
  aliceWs.sendJSON({ type: "recall", to: eve.id, message_id: ack2.id });
  const rc = await bobWs.waitFor((m) => m.type === "recall" && m.message_id === ack2.id);
  check("Bob 收到撤回通知", rc.from === alice.id);
  check("Eve 收不到他人的撤回通知", await eveWs.never((m) => m.type === "recall"));
  eveWs.sendJSON({ type: "recall", to: bob.id, message_id: ack.id });
  check("他人无法撤回不属于自己的消息", await bobWs.never((m) => m.type === "recall" && m.message_id === ack.id));

  console.log("== 非法发送请求 ==");
  const badType = await send(aliceWs, "bt", bob.id, { envelope_type: "evil" });
  check("未知信封类型被拒绝", badType.status === "error");
  const badTo = await send(aliceWs, "bto", "not-a-uuid");
  check("非法接收方 ID 被拒绝", badTo.status === "error");
  const ghost = await send(aliceWs, "gh", "00000000-0000-4000-8000-000000000000");
  check("不存在的接收方被拒绝", ghost.status === "error");

  console.log("== 群消息成员校验 ==");
  const g = await api("/api/v1/groups", { method: "POST", token: alice.token, body: { name: "sec", member_ids: [bob.id] } });
  check("建群成功", g.status === 201);
  const spoof = await send(eveWs, "gs", bob.id, { group_id: g.data.id });
  check("非群成员伪造 group_id 被拒绝", spoof.status === "error");
  const legit = await send(aliceWs, "gl", bob.id, { group_id: g.data.id });
  check("群成员之间的群消息正常投递", legit.status === "delivered");
  const badMember = await api("/api/v1/groups", { method: "POST", token: alice.token, body: { name: "x", member_ids: ["bogus"] } });
  check("建群时非法成员 ID 返回 400", badMember.status === 400);

  console.log("== 黑名单 ==");
  await api(`/api/v1/blocks/${alice.id}`, { method: "POST", token: bob.token });
  const blocked = await send(aliceWs, "bl", bob.id);
  check("被拉黑后消息无法送达", blocked.status === "error");
  aliceWs.sendJSON({ type: "typing", to: bob.id, typing: true });
  check("被拉黑后正在输入不转发", await bobWs.never((m) => m.type === "typing"));
  const pres = await api(`/api/v1/presence/${bob.id}`, { token: alice.token });
  check("被拉黑后看不到对方在线状态", pres.data?.online === false);
  await api(`/api/v1/blocks/${alice.id}`, { method: "DELETE", token: bob.token });
  const unblocked = await send(aliceWs, "ub", bob.id);
  check("解除拉黑后恢复投递", unblocked.status === "delivered");

  console.log("== 公钥上传校验 / 预密钥分发 ==");
  const bad = keys(1, [1]);
  bad.identity.ik_mldsa = fill(10);
  const badUp = await api("/api/v1/keys/upload", { method: "POST", token: bob.token, body: bad });
  check("长度不合法的公钥被拒绝(400)", badUp.status === 400);
  await api("/api/v1/keys/upload", { method: "POST", token: bob.token, body: keys(1, [1, 2, 3]) });
  const self = await api(`/api/v1/keys/bundle/${bob.id}`, { token: bob.token });
  check("不能领取自己的预密钥包", self.status === 400);
  // Bob 重置客户端,以新身份重新上传(编号仍从 1 开始)
  await api("/api/v1/keys/upload", { method: "POST", token: bob.token, body: keys(2, [1, 2]) });
  const cnt = await api("/api/v1/keys/count", { token: bob.token });
  check("身份变更后旧一次性预密钥全部作废", cnt.data?.one_time_prekeys === 2);
  const bundle = await api(`/api/v1/keys/bundle/${bob.id}`, { token: alice.token });
  check(
    "领取到的一次性预密钥属于新身份",
    bundle.data?.one_time_prekey?.public === fill(32, 2) && bundle.data?.identity?.ik_ed === fill(32, 2),
  );
  // 同一身份补充预密钥:不影响剩余的
  await api("/api/v1/keys/upload", { method: "POST", token: bob.token, body: keys(2, [10, 11]) });
  const cnt2 = await api("/api/v1/keys/count", { token: bob.token });
  check("同一身份补充预密钥是追加而非覆盖", cnt2.data?.one_time_prekeys === 3);

  console.log("== 刷新令牌并发轮换 ==");
  const [r1, r2] = await Promise.all([
    api("/api/v1/auth/refresh", { method: "POST", body: { refresh_token: eve.refresh } }),
    api("/api/v1/auth/refresh", { method: "POST", body: { refresh_token: eve.refresh } }),
  ]);
  const okCount = [r1, r2].filter((r) => r.status === 200).length;
  check("同一刷新令牌并发刷新只成功一次", okCount === 1);

  console.log("== 非法路径参数 ==");
  const u404 = await api("/api/v1/users/not-a-uuid", { token: alice.token });
  check("非法用户 ID 返回 404", u404.status === 404);
  const g404 = await api("/api/v1/groups/xyz", { token: alice.token });
  check("非法群 ID 返回 404", g404.status === 404);

  console.log("== 封禁:踢下线并拒绝接入 ==");
  const adminUser = process.env.ADMIN_USERNAME || "admin";
  const adminPass = process.env.ADMIN_PASSWORD || "admin123456";
  const al = await api("/api/v1/admin/login", { method: "POST", body: { username: adminUser, password: adminPass } });
  if (al.status !== 200) {
    console.log("  (跳过:管理员登录失败,请设置 ADMIN_USERNAME/ADMIN_PASSWORD)");
  } else {
    await api(`/api/v1/admin/users/${eve.id}/ban`, { method: "POST", token: al.data.access_token });
    await sleep(500);
    check("封禁后已有 WebSocket 连接被断开", eveWs.closed === true);
    const again = await connectWS(eve.token).then(
      (ws) => new Promise((r) => { ws.addEventListener("close", () => r(true)); setTimeout(() => r(false), 1500); }),
      () => true,
    );
    check("封禁账号无法重新接入 WebSocket", again === true);
    const refreshAfterBan = await api("/api/v1/auth/refresh", {
      method: "POST",
      body: { refresh_token: [r1, r2].find((r) => r.status === 200)?.data?.refresh_token ?? "" },
    });
    check("封禁后刷新令牌失效", refreshAfterBan.status !== 200);
    await api(`/api/v1/admin/users/${eve.id}/unban`, { method: "POST", token: al.data.access_token });
  }

  aliceWs.close();
  bobWs.close();
  eveWs.close();
  console.log(failures === 0 ? "\n全部通过 ✅" : `\n失败 ${failures} 项 ❌`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("测试异常:", e);
  process.exit(1);
});
