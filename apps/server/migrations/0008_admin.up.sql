-- 管理员账号(独立鉴权,与普通用户分离)与审计日志。
CREATE TABLE admin_users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    role          TEXT        NOT NULL DEFAULT 'admin', -- admin | superadmin
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE admin_audit_logs (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id   UUID        REFERENCES admin_users(id) ON DELETE SET NULL,
    action     TEXT        NOT NULL,
    target     TEXT        NOT NULL DEFAULT '',
    detail     TEXT        NOT NULL DEFAULT '',
    ip         TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_created ON admin_audit_logs (created_at DESC);
