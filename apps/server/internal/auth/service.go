// Package auth 实现账号注册/登录/会话(邮箱验证码、Argon2id、JWT + 刷新令牌轮换)。
// 该体系与 E2EE 密钥体系相互独立:服务器掌握账号凭据,但绝不掌握任何用户私钥。
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/pqchat/server/internal/config"
	"github.com/pqchat/server/internal/mailer"
	"github.com/pqchat/server/internal/password"
	"github.com/pqchat/server/internal/token"
)

// 业务错误(由 HTTP 层映射为状态码)。
var (
	ErrEmailTaken         = errors.New("该邮箱已被注册")
	ErrCodeInvalid        = errors.New("验证码错误或已失效")
	ErrRateLimited        = errors.New("操作过于频繁,请稍后再试")
	ErrInvalidCredentials = errors.New("邮箱或密码错误")
	ErrAccountBanned      = errors.New("账号已被封禁")
	ErrInvalidRefresh     = errors.New("刷新令牌无效或已过期")
	ErrSMTPRequired       = errors.New("邮件服务未配置,无法发送验证码")
)

const (
	registerPurpose = "register"
	sendHourlyCap   = 10
	loginFailLimit  = 5
	loginFailWindow = 15 * time.Minute
)

// User 对外暴露的用户视图(不含口令哈希)。
type User struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	Nickname   string    `json:"nickname"`
	AvatarURL  string    `json:"avatar_url"`
	StatusText string    `json:"status_text"`
	CreatedAt  time.Time `json:"created_at"`
}

// TokenPair 一次成功认证返回的令牌与用户信息。
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	User         User
}

// Service 账号服务。
type Service struct {
	pool   *pgxpool.Pool
	rdb    *redis.Client
	mailer *mailer.Mailer
	tokens *token.Manager
	logger *slog.Logger
	cfg    *config.Config
	// dummyHash 用于「邮箱不存在」时也执行一次 Argon2id 校验,
	// 使登录耗时与邮箱是否注册无关,防止通过响应时间枚举账号。
	dummyHash string
}

// NewService 创建账号服务。
func NewService(pool *pgxpool.Pool, rdb *redis.Client, m *mailer.Mailer, tm *token.Manager, logger *slog.Logger, cfg *config.Config) *Service {
	dummy, err := password.Hash("timing-equalizer-not-a-real-password")
	if err != nil {
		logger.Warn("生成占位口令哈希失败", "error", err.Error())
	}
	return &Service{pool: pool, rdb: rdb, mailer: m, tokens: tm, logger: logger, cfg: cfg, dummyHash: dummy}
}

// RevokeAllSessions 吊销用户的全部刷新令牌(管理员封禁时调用),使其无法再续期登录态。
func (s *Service) RevokeAllSessions(ctx context.Context, userID string) error {
	return revokeAllRefreshTokens(ctx, s.pool, userID)
}

// SendRegisterCode 为注册流程发送邮箱验证码(含发送限频与每小时上限)。
func (s *Service) SendRegisterCode(ctx context.Context, email string) error {
	email = normalizeEmail(email)

	taken, err := emailExists(ctx, s.pool, email)
	if err != nil {
		return err
	}
	if taken {
		return ErrEmailTaken
	}

	// 同邮箱最小发送间隔
	intervalKey := "vcode:interval:register:" + email
	ok, err := s.rdb.SetNX(ctx, intervalKey, "1", s.cfg.Verification.SendInterval).Result()
	if err != nil {
		return err
	}
	if !ok {
		return ErrRateLimited
	}

	// 每小时发送次数上限
	countKey := "vcode:count:register:" + email
	cnt, err := s.rdb.Incr(ctx, countKey).Result()
	if err != nil {
		return err
	}
	if cnt == 1 {
		_ = s.rdb.Expire(ctx, countKey, time.Hour).Err()
	}
	if cnt > sendHourlyCap {
		return ErrRateLimited
	}

	code, err := generateCode()
	if err != nil {
		return err
	}
	if err := insertVerification(ctx, s.pool, email, hashCode(email, code), registerPurpose, time.Now().Add(s.cfg.Verification.CodeTTL)); err != nil {
		return err
	}

	switch {
	case s.mailer.Configured():
		if err := s.mailer.SendVerificationCode(email, code, s.cfg.Verification.CodeTTL); err != nil {
			s.logger.Error("发送验证码邮件失败", "email", email, "error", err.Error())
			return err
		}
		s.logger.Info("验证码邮件已发送", "email", email)
	case !s.cfg.App.IsProduction():
		// 开发模式未配置 SMTP:打印验证码便于联调(生产绝不会走到这里)
		s.logger.Warn("SMTP 未配置,开发模式打印验证码", "email", email, "code", code)
	default:
		return ErrSMTPRequired
	}
	return nil
}

// Register 校验验证码并创建账号,成功后签发令牌。
func (s *Service) Register(ctx context.Context, email, code, plainPassword, nickname, userAgent, ip string) (*TokenPair, error) {
	email = normalizeEmail(email)

	v, err := latestActiveVerification(ctx, s.pool, email, registerPurpose)
	if err != nil {
		return nil, err
	}
	if v == nil || v.Attempts >= s.cfg.Verification.MaxAttempts {
		return nil, ErrCodeInvalid
	}
	if hashCode(email, code) != v.CodeHash {
		_ = incrementVerificationAttempts(ctx, s.pool, v.ID)
		return nil, ErrCodeInvalid
	}

	// 并发下二次确认邮箱未被占用
	taken, err := emailExists(ctx, s.pool, email)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, ErrEmailTaken
	}

	pwHash, err := password.Hash(plainPassword)
	if err != nil {
		return nil, err
	}

	// 事务:消费验证码 + 创建用户
	var user User
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := consumeVerification(ctx, tx, v.ID); err != nil {
			return err
		}
		u, err := createUser(ctx, tx, email, pwHash, nickname)
		if err != nil {
			return err
		}
		user = u
		return nil
	})
	if err != nil {
		return nil, err
	}

	return s.issueTokens(ctx, user, userAgent, ip)
}

// Login 校验口令并签发令牌(含失败锁定)。
func (s *Service) Login(ctx context.Context, email, plainPassword, userAgent, ip string) (*TokenPair, error) {
	email = normalizeEmail(email)

	failKey := "login:fail:" + email
	if n, _ := s.rdb.Get(ctx, failKey).Int(); n >= loginFailLimit {
		return nil, ErrRateLimited
	}

	user, hash, banned, err := getUserByEmail(ctx, s.pool, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if s.dummyHash != "" {
				_ = password.Verify(plainPassword, s.dummyHash)
			}
			s.recordLoginFailure(ctx, failKey)
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if err := password.Verify(plainPassword, hash); err != nil {
		s.recordLoginFailure(ctx, failKey)
		return nil, ErrInvalidCredentials
	}
	if banned {
		return nil, ErrAccountBanned
	}

	_ = s.rdb.Del(ctx, failKey).Err()
	return s.issueTokens(ctx, user, userAgent, ip)
}

// Refresh 校验刷新令牌并轮换(吊销旧的、签发新的)。
func (s *Service) Refresh(ctx context.Context, refreshToken, userAgent, ip string) (*TokenPair, error) {
	id, userID, err := getActiveRefreshToken(ctx, s.pool, hashToken(refreshToken))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidRefresh
		}
		return nil, err
	}

	user, banned, err := getUserByID(ctx, s.pool, userID)
	if err != nil {
		return nil, err
	}
	if banned {
		_, _ = revokeRefreshToken(ctx, s.pool, id)
		return nil, ErrAccountBanned
	}

	var pair *TokenPair
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		revoked, err := revokeRefreshToken(ctx, tx, id)
		if err != nil {
			return err
		}
		if !revoked {
			// 并发请求已先一步轮换了该令牌:本次视为无效,避免一个令牌换出两个
			return ErrInvalidRefresh
		}
		access, exp, err := s.tokens.GenerateAccess(user.ID)
		if err != nil {
			return err
		}
		refresh, err := generateRefreshToken()
		if err != nil {
			return err
		}
		if err := insertRefreshToken(ctx, tx, user.ID, hashToken(refresh), userAgent, ip, time.Now().Add(s.cfg.JWT.RefreshTTL)); err != nil {
			return err
		}
		pair = &TokenPair{AccessToken: access, RefreshToken: refresh, ExpiresAt: exp, User: user}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pair, nil
}

// Logout 吊销指定刷新令牌(幂等)。
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	return revokeRefreshTokenByHash(ctx, s.pool, hashToken(refreshToken))
}

// Me 返回当前用户资料。
func (s *Service) Me(ctx context.Context, userID string) (*User, error) {
	user, _, err := getUserByID(ctx, s.pool, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	return &user, nil
}

// issueTokens 签发访问令牌 + 刷新令牌,并持久化刷新令牌哈希。
func (s *Service) issueTokens(ctx context.Context, user User, userAgent, ip string) (*TokenPair, error) {
	access, exp, err := s.tokens.GenerateAccess(user.ID)
	if err != nil {
		return nil, err
	}
	refresh, err := generateRefreshToken()
	if err != nil {
		return nil, err
	}
	if err := insertRefreshToken(ctx, s.pool, user.ID, hashToken(refresh), userAgent, ip, time.Now().Add(s.cfg.JWT.RefreshTTL)); err != nil {
		return nil, err
	}
	return &TokenPair{AccessToken: access, RefreshToken: refresh, ExpiresAt: exp, User: user}, nil
}

func (s *Service) recordLoginFailure(ctx context.Context, key string) {
	n, err := s.rdb.Incr(ctx, key).Result()
	if err == nil && n == 1 {
		_ = s.rdb.Expire(ctx, key, loginFailWindow).Err()
	}
}

// ---- 辅助函数 ----

func normalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

// generateCode 生成 6 位数字验证码(密码学随机)。
func generateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func hashCode(email, code string) string {
	sum := sha256.Sum256([]byte("vcode:" + normalizeEmail(email) + ":" + code))
	return hex.EncodeToString(sum[:])
}

func generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}
