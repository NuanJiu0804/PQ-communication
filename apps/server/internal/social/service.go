// Package social 实现好友关系:好友申请、好友、黑名单与资料。
package social

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 业务错误。
var (
	ErrNotFound        = errors.New("用户不存在")
	ErrSelf            = errors.New("不能对自己执行该操作")
	ErrBlocked         = errors.New("由于黑名单关系,无法操作")
	ErrAlreadyFriends  = errors.New("你们已经是好友")
	ErrRequestExists   = errors.New("已有待处理的好友申请")
	ErrRequestNotFound = errors.New("好友申请不存在或已处理")
)

// PublicProfile 对外可见的用户资料。
type PublicProfile struct {
	ID         string `json:"id"`
	Nickname   string `json:"nickname"`
	AvatarURL  string `json:"avatar_url"`
	StatusText string `json:"status_text"`
}

// FriendRequest 一条好友申请(User 为对端)。
type FriendRequest struct {
	ID        string        `json:"id"`
	User      PublicProfile `json:"user"`
	Note      string        `json:"note"`
	CreatedAt time.Time     `json:"created_at"`
}

// Service 社交关系服务。
type Service struct {
	pool *pgxpool.Pool
}

// NewService 创建服务。
func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// GetProfile 取某用户的公开资料。
func (s *Service) GetProfile(ctx context.Context, userID string) (PublicProfile, error) {
	var p PublicProfile
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, nickname, avatar_url, status_text FROM users WHERE id = $1::uuid`,
		userID).Scan(&p.ID, &p.Nickname, &p.AvatarURL, &p.StatusText)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// SearchByEmail 按邮箱精确查找用户(忽略首尾空白;email 列为 citext,大小写不敏感)。
func (s *Service) SearchByEmail(ctx context.Context, email string) (PublicProfile, error) {
	email = strings.TrimSpace(email)
	var p PublicProfile
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, nickname, avatar_url, status_text FROM users WHERE email = $1`,
		email).Scan(&p.ID, &p.Nickname, &p.AvatarURL, &p.StatusText)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// UpdateProfile 更新本人资料(仅更新非 nil 字段)。
func (s *Service) UpdateProfile(ctx context.Context, userID string, nickname, avatarURL, statusText *string) (PublicProfile, error) {
	var p PublicProfile
	err := s.pool.QueryRow(ctx,
		`UPDATE users SET
		   nickname = COALESCE($2, nickname),
		   avatar_url = COALESCE($3, avatar_url),
		   status_text = COALESCE($4, status_text),
		   updated_at = now()
		 WHERE id = $1::uuid
		 RETURNING id::text, nickname, avatar_url, status_text`,
		userID, nickname, avatarURL, statusText).Scan(&p.ID, &p.Nickname, &p.AvatarURL, &p.StatusText)
	return p, err
}

// SendRequest 发起好友申请。若对方已向你发起待处理申请,则直接互加为好友(autoAccepted=true)。
func (s *Service) SendRequest(ctx context.Context, fromID, toID, note string) (autoAccepted bool, err error) {
	if fromID == toID {
		return false, ErrSelf
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1::uuid)`, toID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}

		var blocked bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM blocks
			 WHERE (user_id = $1::uuid AND blocked_user_id = $2::uuid)
			    OR (user_id = $2::uuid AND blocked_user_id = $1::uuid))`,
			fromID, toID).Scan(&blocked); err != nil {
			return err
		}
		if blocked {
			return ErrBlocked
		}

		var friends bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM friendships WHERE user_id = $1::uuid AND friend_id = $2::uuid)`,
			fromID, toID).Scan(&friends); err != nil {
			return err
		}
		if friends {
			return ErrAlreadyFriends
		}

		// 对方已向我发起待处理申请 → 直接互加
		var revID string
		revErr := tx.QueryRow(ctx,
			`SELECT id::text FROM friend_requests
			 WHERE from_user = $1::uuid AND to_user = $2::uuid AND status = 'pending'`,
			toID, fromID).Scan(&revID)
		if revErr == nil {
			if _, err := tx.Exec(ctx,
				`UPDATE friend_requests SET status = 'accepted', responded_at = now() WHERE id = $1::uuid`, revID); err != nil {
				return err
			}
			autoAccepted = true
			return makeFriends(ctx, tx, fromID, toID)
		} else if !errors.Is(revErr, pgx.ErrNoRows) {
			return revErr
		}

		// 已有正向待处理申请
		var fwd bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM friend_requests
			 WHERE from_user = $1::uuid AND to_user = $2::uuid AND status = 'pending')`,
			fromID, toID).Scan(&fwd); err != nil {
			return err
		}
		if fwd {
			return ErrRequestExists
		}

		_, err := tx.Exec(ctx,
			`INSERT INTO friend_requests (from_user, to_user, note) VALUES ($1::uuid, $2::uuid, $3)`,
			fromID, toID, note)
		return err
	})
	return autoAccepted, err
}

// ListRequests 返回收到的与发出的待处理申请。
func (s *Service) ListRequests(ctx context.Context, userID string) (incoming, outgoing []FriendRequest, err error) {
	incoming, err = s.queryRequests(ctx,
		`SELECT r.id::text, r.note, r.created_at, u.id::text, u.nickname, u.avatar_url, u.status_text
		 FROM friend_requests r JOIN users u ON u.id = r.from_user
		 WHERE r.to_user = $1::uuid AND r.status = 'pending'
		 ORDER BY r.created_at DESC`, userID)
	if err != nil {
		return nil, nil, err
	}
	outgoing, err = s.queryRequests(ctx,
		`SELECT r.id::text, r.note, r.created_at, u.id::text, u.nickname, u.avatar_url, u.status_text
		 FROM friend_requests r JOIN users u ON u.id = r.to_user
		 WHERE r.from_user = $1::uuid AND r.status = 'pending'
		 ORDER BY r.created_at DESC`, userID)
	return incoming, outgoing, err
}

func (s *Service) queryRequests(ctx context.Context, sql, userID string) ([]FriendRequest, error) {
	rows, err := s.pool.Query(ctx, sql, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FriendRequest{}
	for rows.Next() {
		var r FriendRequest
		if err := rows.Scan(&r.ID, &r.Note, &r.CreatedAt, &r.User.ID, &r.User.Nickname, &r.User.AvatarURL, &r.User.StatusText); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AcceptRequest 同意好友申请(仅被申请方可操作)。
func (s *Service) AcceptRequest(ctx context.Context, userID, requestID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var fromID, toID string
		err := tx.QueryRow(ctx,
			`SELECT from_user::text, to_user::text FROM friend_requests
			 WHERE id = $1::uuid AND to_user = $2::uuid AND status = 'pending'`,
			requestID, userID).Scan(&fromID, &toID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRequestNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE friend_requests SET status = 'accepted', responded_at = now() WHERE id = $1::uuid`, requestID); err != nil {
			return err
		}
		return makeFriends(ctx, tx, fromID, toID)
	})
}

// RejectRequest 拒绝好友申请。
func (s *Service) RejectRequest(ctx context.Context, userID, requestID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE friend_requests SET status = 'rejected', responded_at = now()
		 WHERE id = $1::uuid AND to_user = $2::uuid AND status = 'pending'`,
		requestID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRequestNotFound
	}
	return nil
}

// ListFriends 返回好友列表。
func (s *Service) ListFriends(ctx context.Context, userID string) ([]PublicProfile, error) {
	return s.queryProfiles(ctx,
		`SELECT u.id::text, u.nickname, u.avatar_url, u.status_text
		 FROM friendships f JOIN users u ON u.id = f.friend_id
		 WHERE f.user_id = $1::uuid
		 ORDER BY u.nickname`, userID)
}

// RemoveFriend 删除好友(双向)。
func (s *Service) RemoveFriend(ctx context.Context, userID, friendID string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM friendships
		 WHERE (user_id = $1::uuid AND friend_id = $2::uuid)
		    OR (user_id = $2::uuid AND friend_id = $1::uuid)`,
		userID, friendID)
	return err
}

// Block 拉黑:同时解除好友关系并拒绝双方待处理申请。
func (s *Service) Block(ctx context.Context, userID, targetID string) error {
	if userID == targetID {
		return ErrSelf
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO blocks (user_id, blocked_user_id) VALUES ($1::uuid, $2::uuid) ON CONFLICT DO NOTHING`,
			userID, targetID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM friendships
			 WHERE (user_id = $1::uuid AND friend_id = $2::uuid)
			    OR (user_id = $2::uuid AND friend_id = $1::uuid)`,
			userID, targetID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`UPDATE friend_requests SET status = 'rejected', responded_at = now()
			 WHERE status = 'pending'
			   AND ((from_user = $1::uuid AND to_user = $2::uuid) OR (from_user = $2::uuid AND to_user = $1::uuid))`,
			userID, targetID)
		return err
	})
}

// Unblock 取消拉黑。
func (s *Service) Unblock(ctx context.Context, userID, targetID string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM blocks WHERE user_id = $1::uuid AND blocked_user_id = $2::uuid`,
		userID, targetID)
	return err
}

// ListBlocks 返回黑名单。
func (s *Service) ListBlocks(ctx context.Context, userID string) ([]PublicProfile, error) {
	return s.queryProfiles(ctx,
		`SELECT u.id::text, u.nickname, u.avatar_url, u.status_text
		 FROM blocks b JOIN users u ON u.id = b.blocked_user_id
		 WHERE b.user_id = $1::uuid
		 ORDER BY u.nickname`, userID)
}

func (s *Service) queryProfiles(ctx context.Context, sql, userID string) ([]PublicProfile, error) {
	rows, err := s.pool.Query(ctx, sql, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PublicProfile{}
	for rows.Next() {
		var p PublicProfile
		if err := rows.Scan(&p.ID, &p.Nickname, &p.AvatarURL, &p.StatusText); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func makeFriends(ctx context.Context, tx pgx.Tx, a, b string) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO friendships (user_id, friend_id)
		 VALUES ($1::uuid, $2::uuid), ($2::uuid, $1::uuid)
		 ON CONFLICT DO NOTHING`,
		a, b)
	return err
}
