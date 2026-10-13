// Package password 用 Argon2id 对账号口令做加盐哈希与校验。
// 输出/解析采用 PHC 字符串格式:$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>。
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id 参数(贴近 OWASP 推荐)。
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// ErrMismatch 口令与哈希不匹配。
var ErrMismatch = errors.New("口令不匹配")

var b64 = base64.RawStdEncoding

// Hash 用 Argon2id 生成 PHC 格式的口令哈希。
func Hash(plain string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(plain), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify 校验明文口令与 PHC 哈希是否匹配,使用常量时间比较。
func Verify(plain, encoded string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("非法的 argon2id 哈希格式")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return fmt.Errorf("解析版本: %w", err)
	}
	if version != argon2.Version {
		return errors.New("不支持的 argon2 版本")
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return fmt.Errorf("解析参数: %w", err)
	}

	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("解析盐: %w", err)
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("解析哈希: %w", err)
	}

	got := argon2.IDKey([]byte(plain), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}
