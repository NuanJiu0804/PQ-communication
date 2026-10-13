package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// querier 同时由 *pgxpool.Pool 与 pgx.Tx 实现,便于复用查询代码。
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// verification 一条有效验证码记录的最小视图。
type verification struct {
	ID       string
	CodeHash string
	Attempts int
}

func emailExists(ctx context.Context, q querier, email string) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`, email).Scan(&exists)
	return exists, err
}

func insertVerification(ctx context.Context, q querier, email, codeHash, purpose string, expiresAt time.Time) error {
	_, err := q.Exec(ctx,
		`INSERT INTO email_verifications (email, code_hash, purpose, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		email, codeHash, purpose, expiresAt)
	return err
}

// latestActiveVerification 取最近一条未消费、未过期的验证码;无则返回 (nil, nil)。
func latestActiveVerification(ctx context.Context, q querier, email, purpose string) (*verification, error) {
	var v verification
	err := q.QueryRow(ctx,
		`SELECT id::text, code_hash, attempts
		 FROM email_verifications
		 WHERE email = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > now()
		 ORDER BY created_at DESC
		 LIMIT 1`,
		email, purpose).Scan(&v.ID, &v.CodeHash, &v.Attempts)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}

func incrementVerificationAttempts(ctx context.Context, q querier, id string) error {
	_, err := q.Exec(ctx, `UPDATE email_verifications SET attempts = attempts + 1 WHERE id = $1::uuid`, id)
	return err
}

func consumeVerification(ctx context.Context, q querier, id string) error {
	_, err := q.Exec(ctx, `UPDATE email_verifications SET consumed_at = now() WHERE id = $1::uuid`, id)
	return err
}

func createUser(ctx context.Context, q querier, email, passwordHash, nickname string) (User, error) {
	var u User
	err := q.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, nickname)
		 VALUES ($1, $2, $3)
		 RETURNING id::text, email, nickname, avatar_url, status_text, created_at`,
		email, passwordHash, nickname,
	).Scan(&u.ID, &u.Email, &u.Nickname, &u.AvatarURL, &u.StatusText, &u.CreatedAt)
	return u, err
}

// getUserByEmail 返回用户、口令哈希与封禁状态;未找到返回 pgx.ErrNoRows。
func getUserByEmail(ctx context.Context, q querier, email string) (User, string, bool, error) {
	var u User
	var hash string
	var banned bool
	err := q.QueryRow(ctx,
		`SELECT id::text, email, nickname, avatar_url, status_text, created_at, password_hash, is_banned
		 FROM users WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.Email, &u.Nickname, &u.AvatarURL, &u.StatusText, &u.CreatedAt, &hash, &banned)
	return u, hash, banned, err
}

// getUserByID 返回用户与封禁状态;未找到返回 pgx.ErrNoRows。
func getUserByID(ctx context.Context, q querier, id string) (User, bool, error) {
	var u User
	var banned bool
	err := q.QueryRow(ctx,
		`SELECT id::text, email, nickname, avatar_url, status_text, created_at, is_banned
		 FROM users WHERE id = $1::uuid`,
		id,
	).Scan(&u.ID, &u.Email, &u.Nickname, &u.AvatarURL, &u.StatusText, &u.CreatedAt, &banned)
	return u, banned, err
}

func insertRefreshToken(ctx context.Context, q querier, userID, tokenHash, userAgent, ip string, expiresAt time.Time) error {
	_, err := q.Exec(ctx,
		`INSERT INTO refresh_tokens (user_id, token_hash, user_agent, ip, expires_at)
		 VALUES ($1::uuid, $2, $3, $4, $5)`,
		userID, tokenHash, userAgent, ip, expiresAt)
	return err
}

// getActiveRefreshToken 按令牌哈希查找未吊销、未过期的记录;未找到返回 pgx.ErrNoRows。
func getActiveRefreshToken(ctx context.Context, q querier, tokenHash string) (id, userID string, err error) {
	err = q.QueryRow(ctx,
		`SELECT id::text, user_id::text FROM refresh_tokens
		 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()`,
		tokenHash).Scan(&id, &userID)
	return id, userID, err
}

// revokeRefreshToken 吊销一条仍有效的刷新令牌;返回是否确实由本次调用吊销。
// 用 revoked_at IS NULL 做条件,保证并发刷新时同一令牌只能成功轮换一次。
func revokeRefreshToken(ctx context.Context, q querier, id string) (bool, error) {
	tag, err := q.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1::uuid AND revoked_at IS NULL`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// revokeAllRefreshTokens 吊销某用户的全部刷新令牌(封禁时使用)。
func revokeAllRefreshTokens(ctx context.Context, q querier, userID string) error {
	_, err := q.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1::uuid AND revoked_at IS NULL`, userID)
	return err
}

func revokeRefreshTokenByHash(ctx context.Context, q querier, tokenHash string) error {
	_, err := q.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`,
		tokenHash)
	return err
}
