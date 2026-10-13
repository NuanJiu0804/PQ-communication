-- 已读回执与撤回:在信封上记录读时间与撤回时间。
ALTER TABLE message_envelopes ADD COLUMN read_at     TIMESTAMPTZ;
ALTER TABLE message_envelopes ADD COLUMN recalled_at TIMESTAMPTZ;
