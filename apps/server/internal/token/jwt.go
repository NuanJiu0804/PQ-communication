// Package token 负责账号会话的访问令牌(JWT, HS256)。
// 注意:这是账号鉴权令牌,与 E2EE 密钥体系无关。
package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken 访问令牌无效或已过期。
var ErrInvalidToken = errors.New("访问令牌无效或已过期")

// Manager 签发与校验访问令牌。
type Manager struct {
	secret    []byte
	accessTTL time.Duration
}

// NewManager 创建令牌管理器。
func NewManager(secret string, accessTTL time.Duration) *Manager {
	return &Manager{secret: []byte(secret), accessTTL: accessTTL}
}

// AccessClaims 访问令牌声明。
type AccessClaims struct {
	jwt.RegisteredClaims
	Type string `json:"typ"`
}

// GenerateAccess 为指定用户签发访问令牌(typ=access)。
func (m *Manager) GenerateAccess(userID string) (string, time.Time, error) {
	return m.generate(userID, "access")
}

// ParseAccess 校验用户访问令牌并返回用户 ID。
func (m *Manager) ParseAccess(tokenStr string) (string, error) {
	return m.parse(tokenStr, "access")
}

// GenerateAdmin 为管理员签发访问令牌(typ=admin,与用户令牌互不通用)。
func (m *Manager) GenerateAdmin(adminID string) (string, time.Time, error) {
	return m.generate(adminID, "admin")
}

// ParseAdmin 校验管理员访问令牌并返回管理员 ID。
func (m *Manager) ParseAdmin(tokenStr string) (string, error) {
	return m.parse(tokenStr, "admin")
}

func (m *Manager) generate(subject, typ string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(m.accessTTL)
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		Type: typ,
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

func (m *Manager) parse(tokenStr, typ string) (string, error) {
	claims := &AccessClaims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return m.secret, nil
	})
	if err != nil || !tok.Valid || claims.Type != typ || claims.Subject == "" {
		return "", ErrInvalidToken
	}
	return claims.Subject, nil
}
