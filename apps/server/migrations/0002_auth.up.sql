-- 用户账号(账号鉴权体系,与 E2EE 密钥体系相互独立)
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         CITEXT      NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,            -- Argon2id PHC 字符串
    nickname      TEXT        NOT NULL,
    avatar_url    TEXT        NOT NULL DEFAULT '',
    status_text   TEXT        NOT NULL DEFAULT '',
    is_banned     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 邮箱验证码:只存验证码哈希,不存明文;含有效期与失败次数(防爆破)
CREATE TABLE email_verifications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       CITEXT      NOT NULL,
    code_hash   TEXT        NOT NULL,
    purpose     TEXT        NOT NULL,              -- register 等
    attempts    INT         NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_email_verifications_lookup
    ON email_verifications (email, purpose, created_at DESC);

-- 刷新令牌:只存令牌哈希,支持轮换与吊销
CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT        NOT NULL UNIQUE,
    user_agent TEXT        NOT NULL DEFAULT '',
    ip         TEXT        NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id);
