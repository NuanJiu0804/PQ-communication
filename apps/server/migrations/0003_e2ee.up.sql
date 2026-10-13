-- E2EE 公钥分发与消息中继所需的表。服务器只存公钥与密文,绝不存私钥或明文。

-- 设备身份公钥(单设备:每用户一条)
CREATE TABLE device_identities (
    user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    ik_ed      BYTEA       NOT NULL, -- Ed25519 公钥(32)
    ik_x       BYTEA       NOT NULL, -- X25519 公钥(32)
    ik_mldsa   BYTEA       NOT NULL, -- ML-DSA-65 验证公钥(1952)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 当前签名预密钥(每用户一条)
CREATE TABLE signed_prekeys (
    user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    prekey_id  BIGINT      NOT NULL,
    public     BYTEA       NOT NULL, -- X25519 公钥(32)
    sig_ed     BYTEA       NOT NULL, -- Ed25519 签名(64)
    sig_mldsa  BYTEA       NOT NULL, -- ML-DSA 签名(3309)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 当前后量子预密钥(每用户一条)
CREATE TABLE pq_prekeys (
    user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    prekey_id  BIGINT      NOT NULL,
    public_ek  BYTEA       NOT NULL, -- ML-KEM-768 封装公钥(1184)
    sig_ed     BYTEA       NOT NULL,
    sig_mldsa  BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 一次性预密钥(领取即消费)
CREATE TABLE one_time_prekeys (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    prekey_id  BIGINT      NOT NULL,
    public     BYTEA       NOT NULL, -- X25519 公钥(32)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, prekey_id)
);
CREATE INDEX idx_otpk_user ON one_time_prekeys (user_id);

-- 消息信封(只存不透明密文与元数据)
CREATE TABLE message_envelopes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    envelope_type   TEXT        NOT NULL, -- prekey(首条握手) | message
    ciphertext      BYTEA       NOT NULL, -- 不透明密文
    ciphertext_size INT         NOT NULL,
    delivery_status TEXT        NOT NULL DEFAULT 'queued', -- queued | delivered
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ
);
CREATE INDEX idx_envelopes_recipient_queued
    ON message_envelopes (recipient_id, created_at)
    WHERE delivery_status = 'queued';
