// 创建/确认稳定的测试账号(开发模式下验证码打到后端日志)。
// 用法:node scripts/create-accounts.mjs <server-log-path> [base]
import { readFileSync } from "node:fs";

const LOG = process.argv[2];
const BASE = process.argv[3] || "http://localhost:8080";
const PASSWORD = "Pqchat123456";
const users = [
  { email: "alice@pqchat.local", nickname: "Alice" },
  { email: "bob@pqchat.local", nickname: "Bob" },
  { email: "carol@pqchat.local", nickname: "Carol" },
];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
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

console.log(`口令统一为:${PASSWORD}\n`);
for (const u of users) {
  // 若已存在,先尝试直接登录确认可用
  const login = await api("/api/v1/auth/login", { email: u.email, password: PASSWORD });
  if (login.status === 200) {
    console.log(`ℹ️  已存在且可登录:${u.email} / ${PASSWORD}`);
    continue;
  }
  const sc = await api("/api/v1/auth/register/send-code", { email: u.email });
  if (sc.status !== 200 && sc.status !== 204) {
    console.log(`⚠️  send-code ${u.email}: ${sc.status} ${JSON.stringify(sc.data)}`);
  }
  await sleep(600);
  const code = codeFromLog(u.email);
  if (!code) {
    console.log(`❌ ${u.email}:未能从日志读取验证码`);
    continue;
  }
  const r = await api("/api/v1/auth/register", { email: u.email, code, password: PASSWORD, nickname: u.nickname });
  if (r.status === 201) console.log(`✅ 创建成功:${u.email} / ${PASSWORD}（昵称 ${u.nickname}）`);
  else if (r.status === 409) console.log(`ℹ️  已存在:${u.email} / ${PASSWORD}`);
  else console.log(`❌ ${u.email}:${r.status} ${JSON.stringify(r.data)}`);
}
