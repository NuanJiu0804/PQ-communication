// Package groups 实现群组与群成员管理。
// 群消息采用「成对扇出」:发送方对每个成员复用其 1:1 双棘轮会话各加密一份,
// 服务器仅按成员逐条中继密文(群消息的端到端加密因此与单聊同源)。
package groups

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// maxGroupMembers 单个群的成员上限(成对扇出的成本随成员数线性增长)。
const maxGroupMembers = 200

var (
	ErrUserNotFound = errors.New("用户不存在")
	ErrNotFound     = errors.New("群组不存在")
	ErrNotMember    = errors.New("你不是该群成员")
	ErrNotOwner     = errors.New("仅群主可执行该操作")
	ErrBadRequest   = errors.New("请求无效")
)

// Member 群成员。
type Member struct {
	ID        string `json:"id"`
	Nickname  string `json:"nickname"`
	AvatarURL string `json:"avatar_url"`
	Role      string `json:"role"`
}

// Group 群组概要。
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	OwnerID     string    `json:"owner_id"`
	AvatarURL   string    `json:"avatar_url"`
	CreatedAt   time.Time `json:"created_at"`
	MemberCount int       `json:"member_count"`
}

// GroupDetail 群组详情(含成员)。
type GroupDetail struct {
	Group
	Members []Member `json:"members"`
}

// Service 群组服务。
type Service struct {
	pool *pgxpool.Pool
}

// NewService 创建服务。
func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// CreateGroup 创建群组,创建者为群主,并加入指定成员。
func (s *Service) CreateGroup(ctx context.Context, ownerID, name string, memberIDs []string) (Group, error) {
	var g Group
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO groups (name, owner_id) VALUES ($1, $2::uuid) RETURNING id::text, created_at`,
			name, ownerID).Scan(&g.ID, &g.CreatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO group_members (group_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')`,
			g.ID, ownerID); err != nil {
			return err
		}
		for _, m := range memberIDs {
			if m == ownerID || m == "" {
				continue
			}
			tag, err := tx.Exec(ctx,
				`INSERT INTO group_members (group_id, user_id)
				 SELECT $1::uuid, id FROM users WHERE id = $2::uuid
				 ON CONFLICT DO NOTHING`,
				g.ID, m)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				var exists bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1::uuid)`, m).Scan(&exists); err != nil {
					return err
				}
				if !exists {
					return ErrUserNotFound
				}
			}
		}
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM group_members WHERE group_id = $1::uuid`, g.ID).Scan(&g.MemberCount)
	})
	if err != nil {
		return Group{}, err
	}
	g.Name = name
	g.OwnerID = ownerID
	return g, nil
}

// ListGroups 返回用户所在的群组。
func (s *Service) ListGroups(ctx context.Context, userID string) ([]Group, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT g.id::text, g.name, g.owner_id::text, g.avatar_url, g.created_at,
		        (SELECT count(*) FROM group_members m2 WHERE m2.group_id = g.id)
		 FROM groups g
		 JOIN group_members m ON m.group_id = g.id AND m.user_id = $1::uuid
		 ORDER BY g.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.OwnerID, &g.AvatarURL, &g.CreatedAt, &g.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GetGroup 返回群详情(含成员);非成员返回 ErrNotMember。
func (s *Service) GetGroup(ctx context.Context, userID, groupID string) (GroupDetail, error) {
	var d GroupDetail
	if member, err := s.isMember(ctx, groupID, userID); err != nil {
		return d, err
	} else if !member {
		return d, ErrNotMember
	}

	err := s.pool.QueryRow(ctx,
		`SELECT id::text, name, owner_id::text, avatar_url, created_at FROM groups WHERE id = $1::uuid`,
		groupID).Scan(&d.ID, &d.Name, &d.OwnerID, &d.AvatarURL, &d.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}

	members, err := s.members(ctx, groupID)
	if err != nil {
		return d, err
	}
	d.Members = members
	d.MemberCount = len(members)
	return d, nil
}

// Members 返回群成员(供客户端成对扇出);非成员返回 ErrNotMember。
func (s *Service) Members(ctx context.Context, userID, groupID string) ([]Member, error) {
	if member, err := s.isMember(ctx, groupID, userID); err != nil {
		return nil, err
	} else if !member {
		return nil, ErrNotMember
	}
	return s.members(ctx, groupID)
}

// AddMember 添加成员(任一群成员可邀请)。
func (s *Service) AddMember(ctx context.Context, actorID, groupID, userID string) error {
	if member, err := s.isMember(ctx, groupID, actorID); err != nil {
		return err
	} else if !member {
		return ErrNotMember
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1::uuid)`, userID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrUserNotFound
	}
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM group_members WHERE group_id = $1::uuid`, groupID).Scan(&count); err != nil {
		return err
	}
	if count >= maxGroupMembers {
		return ErrBadRequest
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO group_members (group_id, user_id) VALUES ($1::uuid, $2::uuid) ON CONFLICT DO NOTHING`,
		groupID, userID)
	return err
}

// RemoveMember 移除成员(仅群主,且不能移除自己——群主退群请用解散)。
func (s *Service) RemoveMember(ctx context.Context, actorID, groupID, targetID string) error {
	owner, err := s.isOwner(ctx, groupID, actorID)
	if err != nil {
		return err
	}
	if !owner {
		return ErrNotOwner
	}
	if targetID == actorID {
		return ErrBadRequest
	}
	_, err = s.pool.Exec(ctx,
		`DELETE FROM group_members WHERE group_id = $1::uuid AND user_id = $2::uuid AND role <> 'owner'`,
		groupID, targetID)
	return err
}

// Leave 退群;群主退群则解散整个群。
func (s *Service) Leave(ctx context.Context, userID, groupID string) error {
	owner, err := s.isOwner(ctx, groupID, userID)
	if err != nil {
		return err
	}
	if owner {
		_, err := s.pool.Exec(ctx, `DELETE FROM groups WHERE id = $1::uuid`, groupID)
		return err
	}
	_, err = s.pool.Exec(ctx,
		`DELETE FROM group_members WHERE group_id = $1::uuid AND user_id = $2::uuid`, groupID, userID)
	return err
}

// IsMember 供中继层校验:用户是否为群成员。
func (s *Service) IsMember(ctx context.Context, groupID, userID string) (bool, error) {
	return s.isMember(ctx, groupID, userID)
}

func (s *Service) isMember(ctx context.Context, groupID, userID string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1::uuid AND user_id = $2::uuid)`,
		groupID, userID).Scan(&ok)
	return ok, err
}

func (s *Service) isOwner(ctx context.Context, groupID, userID string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1::uuid AND user_id = $2::uuid AND role = 'owner')`,
		groupID, userID).Scan(&ok)
	return ok, err
}

func (s *Service) members(ctx context.Context, groupID string) ([]Member, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT u.id::text, u.nickname, u.avatar_url, m.role
		 FROM group_members m JOIN users u ON u.id = m.user_id
		 WHERE m.group_id = $1::uuid
		 ORDER BY (m.role = 'owner') DESC, u.nickname`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Member{}
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.ID, &m.Nickname, &m.AvatarURL, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
