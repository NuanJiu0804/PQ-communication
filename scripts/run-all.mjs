// 集成测试总入口:依次运行 P2b / P3 / P4 / P5·P6 / 安全加固 五套端到端用例,汇总结果。
//
// 前置:后端 + PostgreSQL/Redis/MinIO 已运行,且后端日志可读(用于取邮箱验证码;
//       未配置 SMTP 的开发模式会把验证码打到日志)。
//
// 用法:
//   node scripts/run-all.mjs <server-log-path> [base]
// 示例:
//   node scripts/run-all.mjs apps/server/server.log http://localhost:8080
//
// 退出码:全部通过 0,任一失败 1,参数缺失 2。
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const LOG = process.argv[2];
const BASE = process.argv[3] || "http://localhost:8080";

if (!LOG) {
  console.error("用法: node scripts/run-all.mjs <server-log-path> [base]");
  process.exit(2);
}
if (!existsSync(LOG)) {
  console.error(`找不到后端日志文件: ${LOG}(验证码需从日志读取,请确认后端已把日志写到该路径)`);
  process.exit(2);
}

const suites = [
  ["P2b 预密钥分发 + WebSocket 密文中继(在线/离线)", "test-p2b.mjs"],
  ["P3  回执(送达/已读)/撤回/正在输入/在线状态", "test-p3.mjs"],
  ["P4  好友申请/同意/拒绝/删除/黑名单/资料/搜索", "test-p4.mjs"],
  ["P5·P6 群组/媒体密文往返/管理后台隐私证明/封禁/审计", "test-p56.mjs"],
  ["安全加固 越权回执/撤回/黑名单/群成员/密钥校验/令牌竞态/封禁踢线", "test-security.mjs"],
];

function runSuite(file) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(here, file), LOG, BASE], { stdio: "inherit" });
    child.on("exit", (code) => resolve(code ?? 1));
    child.on("error", () => resolve(1));
  });
}

const results = [];
for (const [name, file] of suites) {
  console.log(`\n========== ${name} ==========`);
  const code = await runSuite(file);
  results.push([name, code === 0]);
}

console.log("\n================== 汇总 ==================");
let allPass = true;
for (const [name, ok] of results) {
  console.log(`${ok ? "✅ PASS" : "❌ FAIL"}  ${name}`);
  if (!ok) allPass = false;
}
console.log("=========================================");
console.log(allPass ? "全部集成测试通过 ✅" : "存在失败用例 ❌");
process.exit(allPass ? 0 : 1);
