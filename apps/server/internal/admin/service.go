// Package admin 实现管理后台:独立鉴权 + 元数据可视化 + 隐私证明 + 用户管理 + 审计。
// 关键不变量:管理员只能看到元数据与「不可读的密文样本」,绝无解密任何消息的能力。
package admin

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pqchat/server/internal/password"
)

// ErrInvalidCredentials 管理员用户名或密码错误。
var ErrInvalidCredentials = errors.New("用户名或密码错误")

// ErrUserNotFound 目标用户不存在。
var ErrUserNotFound = errors.New("用户不存在")

// Presence 在线连接视图(由消息中继 Hub 提供)。
type Presence interface {
	OnlineCount() int
	Kick(userID string)
}

// Service 管理后台服务。
type Service struct {
	pool   *pgxpool.Pool
	online Presence
}

// NewService 创建服务。
func NewService(pool *pgxpool.Pool, online Presence) *Service {
	return &Service{pool: pool, online: online}
}

// EnsureSeedAdmin 在启动时确保存在一个管理员账号(仅当配置了密码且该用户名不存在时创建)。
func (s *Service) EnsureSeedAdmin(ctx context.Context, username, plainPassword string) error {
	if username == "" || plainPassword == "" {
		return nil
	}
	var exists bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM admin_users WHERE username = $1)`, username).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	hash, err := password.Hash(plainPassword)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO admin_users (username, password_hash, role) VALUES ($1, $2, 'superadmin')`,
		username, hash)
	return err
}

// Login 校验管理员凭据,返回 (管理员 id, 角色)。
func (s *Service) Login(ctx context.Context, username, plainPassword string) (adminID, role string, err error) {
	var hash string
	err = s.pool.QueryRow(ctx,
		`SELECT id::text, password_hash, role FROM admin_users WHERE username = $1`,
		username).Scan(&adminID, &hash, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrInvalidCredentials
	}
	if err != nil {
		return "", "", err
	}
	if err := password.Verify(plainPassword, hash); err != nil {
		return "", "", ErrInvalidCredentials
	}
	return adminID, role, nil
}

// Stats 系统概览指标(均为元数据,不含任何消息内容)。
type Stats struct {
	RegisteredUsers    int `json:"registered_users"`
	OnlineUsers        int `json:"online_users"`
	UsersWithKeys      int `json:"users_with_keys"`
	OneTimePrekeysLeft int `json:"one_time_prekeys_left"`
	Groups             int `json:"groups"`
	TotalMessages      int `json:"total_messages"`
	DeliveredMessages  int `json:"delivered_messages"`
	QueuedMessages     int `json:"queued_messages"`
}

// Stats 汇总系统指标。
func (s *Service) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	st.OnlineUsers = s.online.OnlineCount()
	row := s.pool.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM users),
		  (SELECT count(*) FROM device_identities),
		  (SELECT count(*) FROM one_time_prekeys),
		  (SELECT count(*) FROM groups),
		  (SELECT count(*) FROM message_envelopes),
		  (SELECT count(*) FROM message_envelopes WHERE delivery_status = 'delivered'),
		  (SELECT count(*) FROM message_envelopes WHERE delivery_status = 'queued')`)
	err := row.Scan(&st.RegisteredUsers, &st.UsersWithKeys, &st.OneTimePrekeysLeft,
		&st.Groups, &st.TotalMessages, &st.DeliveredMessages, &st.QueuedMessages)
	return st, err
}

// MessageMeta 一条转发消息的元数据 + 密文样本(隐私证明:服务端只有不可读密文)。
type MessageMeta struct {
	ID               string    `json:"id"`
	SenderID         string    `json:"sender_id"`
	RecipientID      string    `json:"recipient_id"`
	GroupID          *string   `json:"group_id"`
	EnvelopeType     string    `json:"envelope_type"`
	CiphertextSize   int       `json:"ciphertext_size"`
	CiphertextSample string    `json:"ciphertext_sample"` // 前若干字节的 base64,证明不可读
	DeliveryStatus   string    `json:"delivery_status"`
	CreatedAt        time.Time `json:"created_at"`
}

// RecentMessages 返回最近转发的消息元数据(含密文样本,不含明文)。
func (s *Service) RecentMessages(ctx context.Context, limit int) ([]MessageMeta, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, sender_id::text, recipient_id::text, group_id::text,
		       envelope_type, ciphertext_size,
		       encode(substring(ciphertext from 1 for 48), 'base64'),
		       delivery_status, created_at
		FROM message_envelopes
		ORDER BY created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MessageMeta{}
	for rows.Next() {
		var m MessageMeta
		if err := rows.Scan(&m.ID, &m.SenderID, &m.RecipientID, &m.GroupID,
			&m.EnvelopeType, &m.CiphertextSize, &m.CiphertextSample, &m.DeliveryStatus, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// UserRow 用户管理视图(不含口令哈希)。
type UserRow struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Nickname  string    `json:"nickname"`
	IsBanned  bool      `json:"is_banned"`
	CreatedAt time.Time `json:"created_at"`
}

// ListUsers 返回注册用户(按注册时间倒序)。
func (s *Service) ListUsers(ctx context.Context, limit int) ([]UserRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, email, nickname, is_banned, created_at FROM users ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserRow{}
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.ID, &u.Email, &u.Nickname, &u.IsBanned, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetBanned 封禁/解封用户。封禁时立即断开其实时连接。
func (s *Service) SetBanned(ctx context.Context, userID string, banned bool) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET is_banned = $2, updated_at = now() WHERE id = $1::uuid`, userID, banned)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	if banned {
		s.online.Kick(userID)
	}
	return nil
}

// Audit 记录一条管理操作审计。
func (s *Service) Audit(ctx context.Context, adminID, action, target, detail, ip string) {
	_, _ = s.pool.Exec(ctx,
		`INSERT INTO admin_audit_logs (admin_id, action, target, detail, ip)
		 VALUES (NULLIF($1,'')::uuid, $2, $3, $4, $5)`,
		adminID, action, target, detail, ip)
}

// AuditRow 审计日志条目。
type AuditRow struct {
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
}

// ListAudit 返回最近审计日志。
func (s *Service) ListAudit(ctx context.Context, limit int) ([]AuditRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT action, target, detail, ip, created_at FROM admin_audit_logs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditRow{}
	for rows.Next() {
		var a AuditRow
		if err := rows.Scan(&a.Action, &a.Target, &a.Detail, &a.IP, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
