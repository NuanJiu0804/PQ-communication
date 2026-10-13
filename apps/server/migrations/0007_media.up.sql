-- 媒体对象元数据。对象本身是客户端加密后的密文,存于 MinIO;服务器只记录元数据。
CREATE TABLE media_objects (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    object_key   TEXT        NOT NULL UNIQUE,
    uploader_id  UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content_type TEXT        NOT NULL DEFAULT '',
    size         BIGINT      NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_media_uploader ON media_objects (uploader_id);
