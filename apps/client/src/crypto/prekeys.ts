import { keyCount, uploadKeys } from "../api/keys";
import { cryptoPrekeyUpload } from "./core";

/** 服务器剩余一次性预密钥低于该值时补充(与 Rust 侧水位一致)。 */
const LOW_WATER = 5;

/**
 * 同步本机公钥到服务器。
 * - force:登录时总是上传身份/签名预密钥/后量子预密钥(幂等),服务器数据丢失或
 *   首次上传失败时可自愈;
 * - 否则仅在服务器一次性预密钥不足时补充新的一批。
 */
export async function syncPrekeys(force: boolean): Promise<void> {
  const { one_time_prekeys } = await keyCount();
  if (!force && one_time_prekeys >= LOW_WATER) return;
  const bundle = await cryptoPrekeyUpload(one_time_prekeys);
  await uploadKeys(bundle);
}
