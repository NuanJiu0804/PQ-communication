ALTER TABLE message_envelopes DROP COLUMN IF EXISTS group_id;
DROP TABLE IF EXISTS group_members;
DROP TABLE IF EXISTS groups;
