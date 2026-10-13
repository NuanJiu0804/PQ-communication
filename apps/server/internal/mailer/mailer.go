// Package mailer 用 Go 标准库发送邮件(邮箱验证码)。
// QQ 邮箱使用 465 端口的隐式 TLS(SSL),这里用 crypto/tls + net/smtp 实现,
// 不引第三方 SMTP 库,行为可控、跨平台一致。
package mailer

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/smtp"
	"strings"
	"time"

	"github.com/pqchat/server/internal/config"
)

// appName 邮件中展示的系统名称。
const appName = "基于后量子混合密码的端到端加密即时通讯系统"

// ErrNotConfigured SMTP 未配置真实凭据。
var ErrNotConfigured = errors.New("SMTP 未配置")

// Mailer 邮件发送器。
type Mailer struct {
	cfg config.SMTP
}

// New 创建邮件发送器。
func New(cfg config.SMTP) *Mailer { return &Mailer{cfg: cfg} }

// Configured 判断 SMTP 是否已配置真实凭据(排除 .env.example 中的占位值)。
func (m *Mailer) Configured() bool {
	c := m.cfg
	if c.Host == "" || c.Username == "" || c.Password == "" || c.From == "" {
		return false
	}
	if strings.Contains(c.Username, "your_account") || strings.Contains(c.Password, "your_qq_authorization_code") {
		return false
	}
	return true
}

// SendVerificationCode 发送验证码邮件。
func (m *Mailer) SendVerificationCode(to, code string, ttl time.Duration) error {
	if !m.Configured() {
		return ErrNotConfigured
	}
	c := m.cfg

	subject := "【" + appName + "】邮箱验证码"
	body := fmt.Sprintf(
		"您好,\r\n\r\n您的注册验证码是:%s\r\n\r\n验证码 %d 分钟内有效。若非本人操作,请忽略本邮件。\r\n\r\n—— %s",
		code, int(ttl.Minutes()), appName,
	)
	msg := buildMessage(c.FromName, c.From, to, subject, body)

	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	auth := smtp.PlainAuth("", c.Username, c.Password, c.Host)

	if c.UseSSL {
		return sendImplicitTLS(addr, c.Host, auth, c.From, to, msg)
	}
	// 非 SSL 端口(如 587)走 STARTTLS,由 net/smtp.SendMail 处理
	return smtp.SendMail(addr, auth, c.From, []string{to}, msg)
}

// buildMessage 构造一封 UTF-8 纯文本邮件(主题与发件人名用 MIME 编码,正文 base64)。
func buildMessage(fromName, from, to, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s <%s>\r\n", mime.BEncoding.Encode("UTF-8", fromName), from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.BEncoding.Encode("UTF-8", subject))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("\r\n")

	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

// sendImplicitTLS 在 465 端口建立隐式 TLS 连接后发送邮件。
func sendImplicitTLS(addr, host string, auth smtp.Auth, from, to string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil {
		return fmt.Errorf("TLS 连接 SMTP: %w", err)
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("创建 SMTP 客户端: %w", err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP 认证: %w", err)
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
