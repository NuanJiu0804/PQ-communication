// 中继性能测试:端到端转发时延、并发吞吐、离线补发与预密钥包领取耗时。
// 用法:node scripts/bench-relay.mjs <server-log-path> [base] [pairs]
// 说明:负载为 160 字节随机数据(与 100 字节明文的双棘轮消息密文等长),服务器视其为不透明密文。
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";

const LOG = process.argv[2];
const BASE = process.argv[3] || "http://localhost:8080";
const PAIRS = Number(process.argv[4] || 50);
const WSURL = BASE.replace(/^http/, "ws") + "/api/v1/ws";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fill = (n, v = 1) => Buffer.alloc(n, v).toString("base64");
const payload = () => randomBytes(160).toString("base64");

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
  const email = `bench_${tag}_${Date.now()}_${Math.floor(Math.random() * 1e6)}@example.com`;
  await api("/api/v1/auth/register/send-code", { method: "POST", body: { email } });
  let code = null;
  for (let i = 0; i < 20 && !code; i++) {
    await sleep(100);
    code = codeFromLog(email);
  }
  const r = await api("/api/v1/auth/register", { method: "POST", body: { email, code, password: "SuperSecret123", nickname: tag } });
  if (r.status !== 201) throw new Error(`注册失败 ${r.status}`);
  return { token: r.data.access_token, id: r.data.user.id };
}

function connectWS(token) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${WSURL}?token=${encodeURIComponent(token)}`);
    ws.handlers = [];
    ws.addEventListener("message", (ev) => {
      const m = JSON.parse(ev.data);
      for (const h of ws.handlers) h(m);
    });
    ws.onopen = () => resolve(ws);
    ws.onerror = () => reject(new Error("WS 连接失败"));
  });
}

function stats(arr) {
  const s = [...arr].sort((a, b) => a - b);
  const q = (p) => s[Math.min(s.length - 1, Math.floor(s.length * p))];
  const mean = s.reduce((a, b) => a + b, 0) / s.length;
  return { n: s.length, mean: mean.toFixed(2), p50: q(0.5).toFixed(2), p95: q(0.95).toFixed(2), p99: q(0.99).toFixed(2) };
}

async function main() {
  console.log(`注册 ${PAIRS * 2} 个测试用户 …`);
  const users = [];
  for (let i = 0; i < PAIRS * 2; i += 10) {
    users.push(...(await Promise.all(Array.from({ length: Math.min(10, PAIRS * 2 - i) }, (_, k) => setupUser(`u${i + k}`)))));
  }
  const sockets = await Promise.all(users.map((u) => connectWS(u.token)));

  // ---- 1. 单对串行端到端时延 ----
  {
    const [a, b] = [sockets[0], sockets[1]];
    const lat = [];
    for (let i = 0; i < 1000; i++) {
      const t0 = performance.now();
      const got = new Promise((res) => {
        const h = (m) => {
          if (m.type === "message" && m.from === users[0].id) {
            b.handlers.splice(b.handlers.indexOf(h), 1);
            res();
          }
        };
        b.handlers.push(h);
      });
      a.send(JSON.stringify({ type: "send", client_ref: `s${i}`, to: users[1].id, envelope_type: "message", payload: payload() }));
      await got;
      lat.push(performance.now() - t0);
    }
    console.log("RESULT|单对串行转发时延(ms)|" + JSON.stringify(stats(lat)));
  }

  // ---- 2. 并发吞吐:PAIRS 个发送方同时各发 M 条 ----
  {
    const M = 200;
    const lat = [];
    let received = 0;
    const total = PAIRS * M;
    const done = new Promise((res) => {
      for (let p = 0; p < PAIRS; p++) {
        const rx = sockets[2 * p + 1];
        rx.handlers = [
          (m) => {
            if (m.type !== "message") return;
            const sent = Number(m.payload ? 0 : 0);
            void sent;
            lat.push(performance.now() - sendTimes.get(m.from + ":" + (rxCount[p]++)));
            if (++received === total) res();
          },
        ];
      }
    });
    const sendTimes = new Map();
    const rxCount = new Array(PAIRS).fill(0);
    const t0 = performance.now();
    await Promise.all(
      Array.from({ length: PAIRS }, async (_, p) => {
        const tx = sockets[2 * p];
        for (let i = 0; i < M; i++) {
          sendTimes.set(users[2 * p].id + ":" + i, performance.now());
          tx.send(JSON.stringify({ type: "send", client_ref: `c${i}`, to: users[2 * p + 1].id, envelope_type: "message", payload: payload() }));
          if (i % 20 === 19) await sleep(1);
        }
      }),
    );
    await done;
    const secs = (performance.now() - t0) / 1000;
    console.log(`RESULT|并发吞吐|${JSON.stringify({ senders: PAIRS, messages: total, seconds: secs.toFixed(2), msgs_per_sec: (total / secs).toFixed(0) })}`);
    console.log("RESULT|并发下转发时延(ms)|" + JSON.stringify(stats(lat)));
  }

  // ---- 3. 离线暂存与上线补发 ----
  {
    const N = 1000;
    const off = await setupUser("offline");
    const tx = sockets[0];
    let acked = 0;
    const allAck = new Promise((res) => {
      tx.handlers = [(m) => { if (m.type === "ack" && m.status === "queued" && ++acked === N) res(); }];
    });
    for (let i = 0; i < N; i++) {
      const buf = randomBytes(160);
      buf.writeUInt32BE(i, 0);
      tx.send(JSON.stringify({ type: "send", client_ref: `o${i}`, to: off.id, envelope_type: "message", payload: buf.toString("base64") }));
    }
    await allAck;
    const t0 = performance.now();
    const ws = await connectWS(off.token);
    let n = 0;
    let lastId = -1;
    let ordered = true;
    await new Promise((res) => {
      ws.handlers.push((m) => {
        if (m.type !== "message") return;
        const idx = Buffer.from(m.payload, "base64").readUInt32BE(0);
        if (idx <= lastId) ordered = false;
        lastId = idx;
        if (++n === N) res();
      });
    });
    console.log(`RESULT|离线补发|${JSON.stringify({ messages: N, ms: (performance.now() - t0).toFixed(0), all_received: n === N, ordered })}`);
    ws.close();
  }

  // ---- 4. 预密钥包上传与领取 ----
  {
    const owner = users[1];
    const otpks = Array.from({ length: 100 }, (_, i) => ({ id: i + 1, public: fill(32, 2) }));
    await api("/api/v1/keys/upload", {
      method: "POST",
      token: owner.token,
      body: {
        identity: { ik_ed: fill(32), ik_x: fill(32), ik_mldsa: fill(1952) },
        signed_prekey: { id: 1, public: fill(32), sig_ed: fill(64), sig_mldsa: fill(3309) },
        pq_prekey: { id: 1, public_ek: fill(1184), sig_ed: fill(64), sig_mldsa: fill(3309) },
        one_time_prekeys: otpks,
      },
    });
    const lat = [];
    let bytes = 0;
    for (let i = 0; i < 100; i++) {
      const t0 = performance.now();
      const res = await fetch(`${BASE}/api/v1/keys/bundle/${owner.id}`, { headers: { Authorization: `Bearer ${users[0].token}` } });
      const text = await res.text();
      lat.push(performance.now() - t0);
      bytes = text.length;
    }
    console.log("RESULT|预密钥包领取(ms)|" + JSON.stringify({ ...stats(lat), json_bytes: bytes }));
  }

  sockets.forEach((s) => s.close());
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
