// P2b 端到端测试:密钥分发 + WebSocket 中继(在线投递 + 离线暂存)。
// 用法:node scripts/test-p2b.mjs <server-log-path> [base]
import { readFileSync } from "node:fs";

const LOG = process.argv[2];
const BASE = process.argv[3] || "http://localhost:8080";
const WSURL = BASE.replace(/^http/, "ws") + "/api/v1/ws";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b64 = (n) => Buffer.alloc(n, 1).toString("base64");
const enc = (s) => Buffer.from(s).toString("base64");
const dec = (s) => Buffer.from(s, "base64").toString();

let failures = 0;
function check(name, cond) {
  console.log(`${cond ? "  OK " : " FAIL"}  ${name}`);
  if (!cond) failures++;
}

async function api(path, { method = "GET", token, body } = {}) {
  const headers = {};
  if (body) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, data: text ? JSON.parse(text) : null };
}

function codeFromLog(email) {
  const lines = readFileSync(LOG, "utf8").split(/\r?\n/);
  let code = null;
  for (const ln of lines) {
    if (ln.includes(email)) {
      const m = ln.match(/"code":"(\d{6})"/);
      if (m) code = m[1];
    }
  }
  return code;
}

async function setupUser(tag, nickname) {
  const email = `p2b_${tag}_${Date.now()}_${Math.floor(Math.random() * 1e6)}@example.com`;
  await api("/api/v1/auth/register/send-code", { method: "POST", body: { email } });
  await sleep(400);
  const code = codeFromLog(email);
  const r = await api("/api/v1/auth/register", {
    method: "POST",
    body: { email, code, password: "SuperSecret123", nickname },
  });
  if (r.status !== 201) throw new Error(`注册 ${tag} 失败: ${r.status} ${JSON.stringify(r.data)}`);
  return { token: r.data.access_token, id: r.data.user.id, email };
}

function dummyKeys() {
  return {
    identity: { ik_ed: b64(32), ik_x: b64(32), ik_mldsa: b64(1952) },
    signed_prekey: { id: 1, public: b64(32), sig_ed: b64(64), sig_mldsa: b64(3309) },
    pq_prekey: { id: 1, public_ek: b64(1184), sig_ed: b64(64), sig_mldsa: b64(3309) },
    one_time_prekeys: [
      { id: 1, public: b64(32) },
      { id: 2, public: b64(32) },
    ],
  };
}

function connectWS(token) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${WSURL}?token=${encodeURIComponent(token)}`);
    ws.onopen = () => resolve(ws);
    ws.onerror = (e) => reject(new Error("WS 连接失败: " + (e.message || "")));
  });
}
function nextMessage(ws, predicate) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("等待消息超时")), 5000);
    ws.addEventListener("message", function handler(ev) {
      const msg = JSON.parse(ev.data);
      if (!predicate || predicate(msg)) {
        clearTimeout(timer);
        ws.removeEventListener("message", handler);
        resolve(msg);
      }
    });
  });
}

async function main() {
  console.log("== 准备三个用户 ==");
  const alice = await setupUser("alice", "Alice");
  const bob = await setupUser("bob", "Bob");
  const carol = await setupUser("carol", "Carol");
  console.log(`  alice=${alice.id}\n  bob=${bob.id}\n  carol=${carol.id}`);

  console.log("== 上传 Bob/Carol 的公钥 ==");
  const up1 = await api("/api/v1/keys/upload", { method: "POST", token: bob.token, body: dummyKeys() });
  check("Bob 上传密钥 200", up1.status === 200);
  const up2 = await api("/api/v1/keys/upload", { method: "POST", token: carol.token, body: dummyKeys() });
  check("Carol 上传密钥 200", up2.status === 200);

  console.log("== Alice 领取 Bob 的预密钥包 ==");
  const bundle = await api(`/api/v1/keys/bundle/${bob.id}`, { token: alice.token });
  check("领取预密钥包 200", bundle.status === 200);
  check("含身份公钥 ik_mldsa", !!bundle.data?.identity?.ik_mldsa);
  check("含签名预密钥", !!bundle.data?.signed_prekey?.public);
  check("含后量子预密钥", !!bundle.data?.pq_prekey?.public_ek);
  check("消费了一个一次性预密钥(id=1)", bundle.data?.one_time_prekey?.id === 1);

  const cnt = await api("/api/v1/keys/count", { token: bob.token });
  check("Bob 一次性预密钥池剩 1", cnt.data?.one_time_prekeys === 1);

  console.log("== WS 在线投递:Alice → Bob ==");
  const bobWs = await connectWS(bob.token);
  const bobRecv = nextMessage(bobWs, (m) => m.type === "message");
  const aliceWs = await connectWS(alice.token);
  const aliceAck = nextMessage(aliceWs, (m) => m.type === "ack");
  aliceWs.send(
    JSON.stringify({ type: "send", client_ref: "r1", to: bob.id, envelope_type: "message", payload: enc("hello-bob-ciphertext") }),
  );
  const got = await bobRecv;
  check("Bob 收到中继消息", got.type === "message" && got.from === alice.id);
  check("密文原样转发(解出 hello-bob-ciphertext)", dec(got.payload) === "hello-bob-ciphertext");
  const ack = await aliceAck;
  check("Alice 收到 ack 且 status=delivered", ack.type === "ack" && ack.status === "delivered");

  console.log("== WS 离线暂存:Alice → Carol(离线),Carol 上线后补发 ==");
  aliceWs.send(
    JSON.stringify({ type: "send", client_ref: "r2", to: carol.id, envelope_type: "message", payload: enc("hello-carol-offline") }),
  );
  const aliceAck2 = await nextMessage(aliceWs, (m) => m.type === "ack" && m.client_ref === "r2");
  check("发往离线 Carol 的 ack status=queued", aliceAck2.status === "queued");

  await sleep(300);
  const carolWs = await connectWS(carol.token);
  const carolRecv = nextMessage(carolWs, (m) => m.type === "message");
  const cgot = await carolRecv;
  check("Carol 上线后收到离线消息", dec(cgot.payload) === "hello-carol-offline");

  console.log(failures === 0 ? "\n全部通过 ✅" : `\n有 ${failures} 项失败 ❌`);
  process.exitCode = failures === 0 ? 0 : 1;
  await closeAll(aliceWs, bobWs, carolWs);
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
