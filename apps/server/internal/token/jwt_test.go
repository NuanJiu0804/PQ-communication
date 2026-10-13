package token

import (
	"testing"
	"time"
)

func TestGenerateAndParse(t *testing.T) {
	m := NewManager("a-sufficiently-long-test-secret-0123456789", 15*time.Minute)
	tok, exp, err := m.GenerateAccess("user-123")
	if err != nil {
		t.Fatalf("生成令牌失败: %v", err)
	}
	if !exp.After(time.Now()) {
		t.Fatal("过期时间应在未来")
	}
	uid, err := m.ParseAccess(tok)
	if err != nil {
		t.Fatalf("解析令牌失败: %v", err)
	}
	if uid != "user-123" {
		t.Fatalf("用户 ID 不符,期望 user-123,得到 %s", uid)
	}
}

func TestParseRejectsWrongSecret(t *testing.T) {
	tok, _, _ := NewManager("secret-one", time.Minute).GenerateAccess("u")
	if _, err := NewManager("secret-two", time.Minute).ParseAccess(tok); err == nil {
		t.Fatal("不同密钥签发的令牌应校验失败")
	}
}

func TestParseRejectsExpired(t *testing.T) {
	m := NewManager("secret", -time.Minute) // 立即过期
	tok, _, _ := m.GenerateAccess("u")
	if _, err := m.ParseAccess(tok); err == nil {
		t.Fatal("过期令牌应校验失败")
	}
}
