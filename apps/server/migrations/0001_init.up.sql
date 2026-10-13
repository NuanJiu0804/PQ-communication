-- 0001 基线:启用通用扩展
-- citext   : 大小写不敏感文本(后续用于邮箱唯一性约束)
-- pgcrypto : 提供 gen_random_uuid() 等函数
--            (PostgreSQL 13+ 核心已内置 gen_random_uuid,这里显式启用以兼容更早版本)
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
