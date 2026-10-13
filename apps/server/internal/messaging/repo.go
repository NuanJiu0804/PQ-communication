// Package messaging 实现密文消息的实时中继与离线暂存。
// 服务器只转发/暂存不透明密文与元数据,绝不接触明文。
package messaging

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 投递前置检查失败的原因(会以 ack 错误返回给发送方)。
var (
	ErrRecipientNotFound = errors.New("接收方不存在")
	ErrBlocked           = errors.New("由于黑名单关系,消息无法送达")
	ErrNotGroupMember    = errors.New("发送方或接收方不是该群成员")
)

// StoredEnvelope 离线队列中的一条信封。
type StoredEnvelope struct {
	ID           string
	SenderID     string
	EnvelopeType string
	Ciphertext   []byte
	CreatedAt    time.Time
	GroupID      string // 群消息所属群 id;单聊为空
}

// Repo 信封存储。
type Repo struct {
	pool *pgxpool.Pool
}

// NewRepo 创建信封存储。
func NewRepo(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

// CheckDeliverable 校验发送方能否向接收方投递:接收方存在、双方无拉黑关系;
// 群消息还要求双方当前都是该群成员(防止伪造 group_id 或向已退群成员扇出)。
func (r *Repo) CheckDeliverable(ctx context.Context, senderID, recipientID, groupID string) error {
	var exists, blocked bool
	if err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE id = $2::uuid),
		        EXISTS(SELECT 1 FROM blocks
		               WHERE (user_id = $1::uuid AND blocked_user_id = $2::uuid)
		                  OR (user_id = $2::uuid AND blocked_user_id = $1::uuid))`,
		senderID, recipientID).Scan(&exists, &blocked); err != nil {
		return err
	}
	if !exists {
		return ErrRecipientNotFound
	}
	if blocked {
		return ErrBlocked
	}
	if groupID == "" {
		return nil
	}
	var members int
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM group_members
		 WHERE group_id = $1::uuid AND user_id IN ($2::uuid, $3::uuid)`,
		groupID, senderID, recipientID).Scan(&members); err != nil {
		return err
	}
	if members != 2 {
		return ErrNotGroupMember
	}
	return nil
}

// IsBlocked 判断两用户之间是否存在任一方向的拉黑关系。
func (r *Repo) IsBlocked(ctx context.Context, a, b string) (bool, error) {
	var blocked bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM blocks
		 WHERE (user_id = $1::uuid AND blocked_user_id = $2::uuid)
		    OR (user_id = $2::uuid AND blocked_user_id = $1::uuid))`,
		a, b).Scan(&blocked)
	return blocked, err
}

// IsBanned 判断用户是否被封禁(不存在的用户视为封禁)。
func (r *Repo) IsBanned(ctx context.Context, userID string) (bool, error) {
	var banned bool
	err := r.pool.QueryRow(ctx, `SELECT is_banned FROM users WHERE id = $1::uuid`, userID).Scan(&banned)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	return banned, err
}

// Insert 持久化一条信封(初始状态 queued),返回其 ID 与创建时间。
func (r *Repo) Insert(ctx context.Context, senderID, recipientID, envType, groupID string, ciphertext []byte) (string, time.Time, error) {
	var id string
	var createdAt time.Time
	err := r.pool.QueryRow(ctx,
		`INSERT INTO message_envelopes (sender_id, recipient_id, envelope_type, ciphertext, ciphertext_size, group_id)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, NULLIF($6, '')::uuid)
		 RETURNING id::text, created_at`,
		senderID, recipientID, envType, ciphertext, len(ciphertext), groupID).Scan(&id, &createdAt)
	return id, createdAt, err
}

// MarkDelivered 把信封标记为已投递(幂等)。
func (r *Repo) MarkDelivered(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE message_envelopes SET delivery_status = 'delivered', delivered_at = now()
		 WHERE id = $1::uuid AND delivery_status = 'queued'`, id)
	return err
}

// MarkRead 由接收方把信封标记为已读,返回原发送者 ID。
// 只有该信封的接收方才能标记(ok=false 表示无权或信封不存在);重复标记幂等。
func (r *Repo) MarkRead(ctx context.Context, id, readerID string) (senderID string, ok bool, err error) {
	err = r.pool.QueryRow(ctx,
		`UPDATE message_envelopes SET read_at = COALESCE(read_at, now())
		 WHERE id = $1::uuid AND recipient_id = $2::uuid AND recalled_at IS NULL
		 RETURNING sender_id::text`, id, readerID).Scan(&senderID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return senderID, true, nil
}

// MarkRecalled 撤回信封:仅发送者可撤回;同时清空密文(连服务器也不再保留内容)。
// 返回该信封的接收方 ID;ok=false 表示非本人消息、已撤回或不存在。
func (r *Repo) MarkRecalled(ctx context.Context, id, senderID string) (recipientID string, ok bool, err error) {
	err = r.pool.QueryRow(ctx,
		`UPDATE message_envelopes
		 SET recalled_at = now(), delivery_status = 'recalled',
		     ciphertext = ''::bytea, ciphertext_size = 0
		 WHERE id = $1::uuid AND sender_id = $2::uuid AND recalled_at IS NULL
		 RETURNING recipient_id::text`,
		id, senderID).Scan(&recipientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return recipientID, true, nil
}

// Queued 按时间顺序返回某接收方所有待投递的信封。
func (r *Repo) Queued(ctx context.Context, recipientID string) ([]StoredEnvelope, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id::text, sender_id::text, envelope_type, ciphertext, created_at, COALESCE(group_id::text, '')
		 FROM message_envelopes
		 WHERE recipient_id = $1::uuid AND delivery_status = 'queued'
		 ORDER BY created_at, id`, recipientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StoredEnvelope
	for rows.Next() {
		var e StoredEnvelope
		if err := rows.Scan(&e.ID, &e.SenderID, &e.EnvelopeType, &e.Ciphertext, &e.CreatedAt, &e.GroupID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
