//! 本地加密存储:用 bundled SQLite 作容器,内容用应用层 AEAD 加密
//! (XChaCha20-Poly1305,密钥由登录口令经 Argon2id 派生)。
//!
//! 这是 SQLCipher 的同级方案:加密路径完全用 crypto-core 的成熟原语完成,
//! 无 OpenSSL 原生依赖,Windows/Ubuntu 一致。

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crypto_core::store as cstore;

/// 已解锁的加密存储。持有派生密钥与数据库连接。
pub struct SecureStore {
    conn: Connection,
    key: [u8; 32],
}

impl SecureStore {
    /// 打开(或创建)指定路径的存储,用口令派生密钥解锁。
    pub fn unlock(path: &Path, password: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL)",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v BLOB NOT NULL)",
            [],
        )
        .map_err(|e| e.to_string())?;

        // 盐(非机密)持久化于 meta 表;首次创建。
        let salt_row: Option<Vec<u8>> = conn
            .query_row("SELECT v FROM meta WHERE k = 'salt'", [], |r| r.get(0))
            .optional()
            .map_err(|e| e.to_string())?;
        let salt: [u8; cstore::SALT_LEN] = match salt_row {
            Some(v) => v.try_into().map_err(|_| "存储盐长度异常".to_string())?,
            None => {
                let s = cstore::generate_salt();
                conn.execute("INSERT INTO meta (k, v) VALUES ('salt', ?1)", params![&s[..]])
                    .map_err(|e| e.to_string())?;
                s
            }
        };

        let key = cstore::derive_key(password.as_bytes(), &salt).map_err(|e| e.to_string())?;
        Ok(Self { conn, key })
    }

    /// 加密并写入一条命名值。
    pub fn put(&self, name: &str, plaintext: &[u8]) -> Result<(), String> {
        let blob = cstore::seal(&self.key, plaintext);
        self.conn
            .execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?1, ?2)", params![name, blob])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// 读取并解密一条命名值;不存在返回 None,口令错误/被篡改返回 Err。
    pub fn get(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT v FROM kv WHERE k = ?1", params![name], |r| r.get(0))
            .optional()
            .map_err(|e| e.to_string())?;
        match blob {
            Some(b) => Ok(Some(cstore::open(&self.key, &b).map_err(|e| e.to_string())?)),
            None => Ok(None),
        }
    }
}
