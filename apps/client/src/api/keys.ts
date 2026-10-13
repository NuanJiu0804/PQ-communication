import { apiRequest } from "./client";
import type { FetchedBundle, UploadBundle } from "../crypto/core";

// 上传本机公钥(身份 + 预密钥)。
export function uploadKeys(bundle: UploadBundle): Promise<{ message: string }> {
  return apiRequest("/api/v1/keys/upload", { method: "POST", auth: true, body: bundle });
}

// 领取目标用户的预密钥包(会消费其一个一次性预密钥)。
export function fetchBundle(userId: string): Promise<FetchedBundle> {
  return apiRequest(`/api/v1/keys/bundle/${userId}`, { auth: true });
}

// 查询本人剩余一次性预密钥数量。
export function keyCount(): Promise<{ one_time_prekeys: number }> {
  return apiRequest("/api/v1/keys/count", { auth: true });
}

// 查询目标用户是否在线。
export function fetchPresence(userId: string): Promise<{ online: boolean }> {
  return apiRequest(`/api/v1/presence/${userId}`, { auth: true });
}
