// P3 测试:已读/送达回执、撤回、正在输入、在线状态。
// 用法:node scripts/test-p3.mjs <server-log-path> [base]
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
  const email = `p3_${tag}_${Date.now()}_${Math.floor(Math.random() * 1e6)}@example.com`;
  await api("/api/v1/auth/register/send-code", { method: "POST", body: { email } });
  await sleep(400);
  const code = codeFromLog(email);
  const r = await api("/api/v1/auth/register", {
    method: "POST",
    body: { email, code, password: "SuperSecret123", nickname: tag },
  });
  if (r.status !== 201) throw new Error(`注册 ${tag} 失败: ${r.status}`);
  return { token: r.data.access_token, id: r.data.user.id };
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
        setTimeout(() => {
          const idx = waiters.indexOf(w);
          if (idx >= 0) waiters.splice(idx, 1);
          rej(new Error("等待消息超时"));
        }, timeout);
      });
    ws.sendJSON = (obj) => ws.send(JSON.stringify(obj));
    ws.onopen = () => resolve(ws);
    ws.onerror = (e) => reject(new Error("WS 错误: " + (e.message || "")));
  });
}

async function main() {
  const alice = await setupUser("alice");
  const bob = await setupUser("bob");
  console.log(`alice=${alice.id}\nbob=${bob.id}`);

  console.log("== 在线状态:Bob 未连接 ==");
  const p0 = await api(`/api/v1/presence/${bob.id}`, { token: alice.token });
  check("Bob 离线时 presence online=false", p0.data?.online === false);

  console.log("== 送达回执(离线 → 上线)==");
  const aliceWs = await connectWS(alice.token);
  aliceWs.sendJSON({ type: "send", client_ref: "r1", to: bob.id, envelope_type: "message", payload: enc("m1") });
  const ack1 = await aliceWs.waitFor((m) => m.type === "ack" && m.client_ref === "r1");
  check("Alice 发往离线 Bob 的 ack=queued", ack1.status === "queued");
  const id1 = ack1.id;

  const bobWs = await connectWS(bob.token);
  const p1 = await api(`/api/v1/presence/${bob.id}`, { token: alice.token });
  check("Bob 连接后 presence online=true", p1.data?.online === true);

  await bobWs.waitFor((m) => m.type === "message" && m.id === id1);
  const deliveredReceipt = await aliceWs.waitFor(
    (m) => m.type === "receipt" && m.message_id === id1 && m.status === "delivered",
  );
  check("Alice 收到送达回执(delivered)", !!deliveredReceipt);

  console.log("== 已读回执 ==");
  bobWs.sendJSON({ type: "receipt", to: alice.id, message_id: id1, status: "read" });
  const readReceipt = await aliceWs.waitFor((m) => m.type === "receipt" && m.message_id === id1 && m.status === "read");
  check("Alice 收到已读回执(read)", !!readReceipt);

  console.log("== 正在输入 ==");
  aliceWs.sendJSON({ type: "typing", to: bob.id, typing: true });
  const typing = await bobWs.waitFor((m) => m.type === "typing" && m.from === alice.id);
  check("Bob 收到 Alice 正在输入", typing.typing === true);

  console.log("== 撤回 ==");
  aliceWs.sendJSON({ type: "send", client_ref: "r2", to: bob.id, envelope_type: "message", payload: enc("to-recall") });
  const ack2 = await aliceWs.waitFor((m) => m.type === "ack" && m.client_ref === "r2");
  const id2 = ack2.id;
  await bobWs.waitFor((m) => m.type === "message" && m.id === id2);
  aliceWs.sendJSON({ type: "recall", to: bob.id, message_id: id2 });
  const recall = await bobWs.waitFor((m) => m.type === "recall" && m.message_id === id2 && m.from === alice.id);
  check("Bob 收到撤回通知", !!recall);

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
