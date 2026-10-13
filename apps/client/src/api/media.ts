import { apiRequest } from "./client";

// 申请预签名上传 URL(服务器生成对象键并登记元数据)。
export const createUploadUrl = (contentType: string, size: number): Promise<{ object_key: string; upload_url: string }> =>
  apiRequest("/api/v1/media/upload-url", {
    method: "POST",
    auth: true,
    body: { content_type: contentType, size },
  });

// 申请预签名下载 URL。
export const getDownloadUrl = (objectKey: string): Promise<{ download_url: string }> =>
  apiRequest(`/api/v1/media/download-url?key=${encodeURIComponent(objectKey)}`, { auth: true });
