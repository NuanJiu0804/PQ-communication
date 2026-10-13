-- 社交关系:好友申请、好友、黑名单。

CREATE TABLE friend_requests (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_user    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    note         TEXT        NOT NULL DEFAULT '',
    status       TEXT        NOT NULL DEFAULT 'pending', -- pending | accepted | rejected
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    responded_at TIMESTAMPTZ,
    CHECK (from_user <> to_user)
);
-- 同一方向至多一条待处理申请
CREATE UNIQUE INDEX idx_friend_req_pending
    ON friend_requests (from_user, to_user) WHERE status = 'pending';
CREATE INDEX idx_friend_req_to ON friend_requests (to_user) WHERE status = 'pending';

-- 好友关系(接受后双向各存一行,便于查询)
CREATE TABLE friendships (
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    friend_id  UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, friend_id)
);

-- 黑名单
CREATE TABLE blocks (
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_user_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, blocked_user_id)
);
