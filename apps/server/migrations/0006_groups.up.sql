-- 群组与群成员;消息信封增加可选 group_id(群消息采用成对扇出,每成员一条信封)。

CREATE TABLE groups (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT        NOT NULL,
    owner_id   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    avatar_url TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE group_members (
    group_id  UUID        NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role      TEXT        NOT NULL DEFAULT 'member', -- owner | member
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX idx_group_members_user ON group_members (user_id);

ALTER TABLE message_envelopes ADD COLUMN group_id UUID REFERENCES groups(id) ON DELETE SET NULL;
