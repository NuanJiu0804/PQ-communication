// 生成 1024x1024 的应用图标源图(teal 圆角底 + 简洁消息卡片标记),
// 供 `tauri icon` 派生各平台所需尺寸(png/ico/icns)。
// 纯 Node 实现,无第三方依赖,Windows/Linux 一致。
import { deflateSync } from "node:zlib";
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const W = 1024;
const H = 1024;
const buf = Buffer.alloc(W * H * 4); // RGBA,初始全透明

// 颜色(与设计规范一致)
const TEAL = [14, 124, 123, 255]; // #0E7C7B
const TEAL_DK = [11, 100, 99, 255]; // #0B6463
const PAPER = [250, 250, 250, 255]; // #FAFAFA

function setPx(x, y, c) {
  if (x < 0 || y < 0 || x >= W || y >= H) return;
  const i = (y * W + x) * 4;
  buf[i] = c[0];
  buf[i + 1] = c[1];
  buf[i + 2] = c[2];
  buf[i + 3] = c[3];
}

// 判断点是否落在圆角矩形内
function inRoundRect(x, y, rx, ry, rw, rh, r) {
  if (x < rx || y < ry || x >= rx + rw || y >= ry + rh) return false;
  const dx = Math.min(x - rx, rx + rw - 1 - x);
  const dy = Math.min(y - ry, ry + rh - 1 - y);
  if (dx >= r || dy >= r) return true;
  const cx = r - dx;
  const cy = r - dy;
  return cx * cx + cy * cy <= r * r;
}

for (let y = 0; y < H; y++) {
  for (let x = 0; x < W; x++) {
    let c = null;
    if (inRoundRect(x, y, 0, 0, W, H, 180)) c = TEAL; // 圆角底
    if (inRoundRect(x, y, 250, 250, 524, 460, 70)) c = PAPER; // 消息卡片
    if (inRoundRect(x, y, 330, 380, 364, 60, 30)) c = TEAL_DK; // 消息条 1
    if (inRoundRect(x, y, 330, 500, 240, 60, 30)) c = TEAL_DK; // 消息条 2
    if (c) setPx(x, y, c);
  }
}

// 卡片左下角的气泡小尾巴
for (let y = 660; y < 745; y++) {
  for (let x = 300; x < 385; x++) {
    if (x - 300 + (745 - y) < 85) setPx(x, y, PAPER);
  }
}

// ---- 最小 PNG 编码 ----
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(b) {
  let c = 0xffffffff;
  for (let i = 0; i < b.length; i++) c = CRC_TABLE[(c ^ b[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeData = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typeData), 0);
  return Buffer.concat([len, typeData, crc]);
}

// 每行前置一个 filter 字节(0 = None)
const raw = Buffer.alloc(H * (1 + W * 4));
for (let y = 0; y < H; y++) {
  const rowStart = y * (1 + W * 4);
  raw[rowStart] = 0;
  buf.copy(raw, rowStart + 1, y * W * 4, (y + 1) * W * 4);
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(W, 0);
ihdr.writeUInt32BE(H, 4);
ihdr[8] = 8; // 位深
ihdr[9] = 6; // 颜色类型 RGBA
ihdr[10] = 0; // 压缩
ihdr[11] = 0; // 过滤
ihdr[12] = 0; // 隔行

const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk("IHDR", ihdr),
  chunk("IDAT", deflateSync(raw)),
  chunk("IEND", Buffer.alloc(0)),
]);

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "src-tauri");
mkdirSync(outDir, { recursive: true });
const outPath = join(outDir, "app-icon.png");
writeFileSync(outPath, png);
console.log("已生成图标源图: " + outPath + " (1024x1024)");
