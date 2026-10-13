// Package keys 实现 E2EE 公钥(身份/预密钥)的上传与分发。
// 服务器只接触公钥;私钥永远留在客户端。
package keys

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoKeys 目标用户尚未上传密钥。
var ErrNoKeys = errors.New("目标用户尚未发布密钥")

// ErrInvalidKeys 上传的公钥格式不合法(长度不符等)。
var ErrInvalidKeys = errors.New("公钥格式不合法")

// 各类公钥/签名的固定长度(与客户端 crypto-core 一致)。
const (
	ed25519PubLen  = 32
	x25519PubLen   = 32
	ed25519SigLen  = 64
	mldsa65VKLen   = 1952
	mldsa65SigLen  = 3309
	mlkem768EKLen  = 1184
	maxOTPKsUpload = 100
)

// Validate 校验上传公钥的长度与数量,拒绝畸形数据进入分发环节
// (否则发起方会领取到无法使用的预密钥包)。签名的有效性由客户端在使用前验证。
func (r *UploadRequest) Validate() error {
	ok := len(r.Identity.IKEd) == ed25519PubLen &&
		len(r.Identity.IKX) == x25519PubLen &&
		len(r.Identity.IKMldsa) == mldsa65VKLen &&
		len(r.SignedPreKey.Public) == x25519PubLen &&
		len(r.SignedPreKey.SigEd) == ed25519SigLen &&
		len(r.SignedPreKey.SigMldsa) == mldsa65SigLen &&
		len(r.PqPreKey.PublicEK) == mlkem768EKLen &&
		len(r.PqPreKey.SigEd) == ed25519SigLen &&
		len(r.PqPreKey.SigMldsa) == mldsa65SigLen &&
		r.SignedPreKey.ID > 0 && r.SignedPreKey.ID <= 0xFFFFFFFF &&
		r.PqPreKey.ID > 0 && r.PqPreKey.ID <= 0xFFFFFFFF &&
		len(r.OneTimePreKeys) <= maxOTPKsUpload
	if !ok {
		return ErrInvalidKeys
	}
	for _, k := range r.OneTimePreKeys {
		if len(k.Public) != x25519PubLen || k.ID <= 0 || k.ID > 0xFFFFFFFF {
			return ErrInvalidKeys
		}
	}
	return nil
}

// IdentityKeys 身份公钥。字节字段经 JSON 自动 base64 编解码。
type IdentityKeys struct {
	IKEd    []byte `json:"ik_ed" binding:"required"`
	IKX     []byte `json:"ik_x" binding:"required"`
	IKMldsa []byte `json:"ik_mldsa" binding:"required"`
}

// SignedPreKey 签名预密钥(含混合签名)。
type SignedPreKey struct {
	ID       int64  `json:"id"`
	Public   []byte `json:"public" binding:"required"`
	SigEd    []byte `json:"sig_ed" binding:"required"`
	SigMldsa []byte `json:"sig_mldsa" binding:"required"`
}

// PqPreKey 后量子预密钥(含混合签名)。
type PqPreKey struct {
	ID       int64  `json:"id"`
	PublicEK []byte `json:"public_ek" binding:"required"`
	SigEd    []byte `json:"sig_ed" binding:"required"`
	SigMldsa []byte `json:"sig_mldsa" binding:"required"`
}

// OneTimePreKey 一次性预密钥。
type OneTimePreKey struct {
	ID     int64  `json:"id"`
	Public []byte `json:"public" binding:"required"`
}

// UploadRequest 客户端上传的整套公钥。
type UploadRequest struct {
	Identity       IdentityKeys    `json:"identity" binding:"required"`
	SignedPreKey   SignedPreKey    `json:"signed_prekey" binding:"required"`
	PqPreKey       PqPreKey        `json:"pq_prekey" binding:"required"`
	OneTimePreKeys []OneTimePreKey `json:"one_time_prekeys"`
}

// PreKeyBundle 分发给发起方的预密钥包。
type PreKeyBundle struct {
	Identity      IdentityKeys   `json:"identity"`
	SignedPreKey  SignedPreKey   `json:"signed_prekey"`
	PqPreKey      PqPreKey       `json:"pq_prekey"`
	OneTimePreKey *OneTimePreKey `json:"one_time_prekey,omitempty"`
}

// Service 密钥分发服务。
type Service struct {
	pool *pgxpool.Pool
}

// NewService 创建密钥分发服务。
func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Upload 写入/更新用户的身份与预密钥。
// 若身份公钥发生变化(客户端重置/重装后生成了新身份),旧身份遗留的一次性预密钥
// 必须全部作废:它们的私钥已不存在,且编号会与新身份的预密钥冲突(ON CONFLICT DO NOTHING
// 会保留旧公钥),导致他人领取到无法解密的预密钥包。
func (s *Service) Upload(ctx context.Context, userID string, req *UploadRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var oldEd []byte
		err := tx.QueryRow(ctx,
			`SELECT ik_ed FROM device_identities WHERE user_id = $1::uuid FOR UPDATE`, userID).Scan(&oldEd)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("读取身份公钥: %w", err)
		}
		if err == nil && !bytes.Equal(oldEd, req.Identity.IKEd) {
			if _, err := tx.Exec(ctx, `DELETE FROM one_time_prekeys WHERE user_id = $1::uuid`, userID); err != nil {
				return fmt.Errorf("清理旧一次性预密钥: %w", err)
			}
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO device_identities (user_id, ik_ed, ik_x, ik_mldsa, updated_at)
			 VALUES ($1::uuid, $2, $3, $4, now())
			 ON CONFLICT (user_id) DO UPDATE
			   SET ik_ed = EXCLUDED.ik_ed, ik_x = EXCLUDED.ik_x,
			       ik_mldsa = EXCLUDED.ik_mldsa, updated_at = now()`,
			userID, req.Identity.IKEd, req.Identity.IKX, req.Identity.IKMldsa); err != nil {
			return fmt.Errorf("写入身份公钥: %w", err)
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO signed_prekeys (user_id, prekey_id, public, sig_ed, sig_mldsa)
			 VALUES ($1::uuid, $2, $3, $4, $5)
			 ON CONFLICT (user_id) DO UPDATE
			   SET prekey_id = EXCLUDED.prekey_id, public = EXCLUDED.public,
			       sig_ed = EXCLUDED.sig_ed, sig_mldsa = EXCLUDED.sig_mldsa, created_at = now()`,
			userID, req.SignedPreKey.ID, req.SignedPreKey.Public, req.SignedPreKey.SigEd, req.SignedPreKey.SigMldsa); err != nil {
			return fmt.Errorf("写入签名预密钥: %w", err)
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO pq_prekeys (user_id, prekey_id, public_ek, sig_ed, sig_mldsa)
			 VALUES ($1::uuid, $2, $3, $4, $5)
			 ON CONFLICT (user_id) DO UPDATE
			   SET prekey_id = EXCLUDED.prekey_id, public_ek = EXCLUDED.public_ek,
			       sig_ed = EXCLUDED.sig_ed, sig_mldsa = EXCLUDED.sig_mldsa, created_at = now()`,
			userID, req.PqPreKey.ID, req.PqPreKey.PublicEK, req.PqPreKey.SigEd, req.PqPreKey.SigMldsa); err != nil {
			return fmt.Errorf("写入后量子预密钥: %w", err)
		}

		for _, opk := range req.OneTimePreKeys {
			if _, err := tx.Exec(ctx,
				`INSERT INTO one_time_prekeys (user_id, prekey_id, public)
				 VALUES ($1::uuid, $2, $3)
				 ON CONFLICT (user_id, prekey_id) DO NOTHING`,
				userID, opk.ID, opk.Public); err != nil {
				return fmt.Errorf("写入一次性预密钥: %w", err)
			}
		}
		return nil
	})
}

// FetchBundle 取目标用户的预密钥包,并消费一个一次性预密钥(若有)。
func (s *Service) FetchBundle(ctx context.Context, targetID string) (*PreKeyBundle, error) {
	var bundle PreKeyBundle

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT ik_ed, ik_x, ik_mldsa FROM device_identities WHERE user_id = $1::uuid`,
			targetID).Scan(&bundle.Identity.IKEd, &bundle.Identity.IKX, &bundle.Identity.IKMldsa)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoKeys
			}
			return err
		}

		if err := tx.QueryRow(ctx,
			`SELECT prekey_id, public, sig_ed, sig_mldsa FROM signed_prekeys WHERE user_id = $1::uuid`,
			targetID).Scan(&bundle.SignedPreKey.ID, &bundle.SignedPreKey.Public,
			&bundle.SignedPreKey.SigEd, &bundle.SignedPreKey.SigMldsa); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoKeys
			}
			return err
		}

		if err := tx.QueryRow(ctx,
			`SELECT prekey_id, public_ek, sig_ed, sig_mldsa FROM pq_prekeys WHERE user_id = $1::uuid`,
			targetID).Scan(&bundle.PqPreKey.ID, &bundle.PqPreKey.PublicEK,
			&bundle.PqPreKey.SigEd, &bundle.PqPreKey.SigMldsa); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoKeys
			}
			return err
		}

		// 原子地弹出一个一次性预密钥
		var opk OneTimePreKey
		err = tx.QueryRow(ctx,
			`DELETE FROM one_time_prekeys
			 WHERE id = (
			   SELECT id FROM one_time_prekeys
			   WHERE user_id = $1::uuid
			   ORDER BY prekey_id
			   LIMIT 1
			   FOR UPDATE SKIP LOCKED
			 )
			 RETURNING prekey_id, public`,
			targetID).Scan(&opk.ID, &opk.Public)
		if err == nil {
			bundle.OneTimePreKey = &opk
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &bundle, nil
}

// CountOneTimePreKeys 返回用户剩余的一次性预密钥数量(预密钥池水位)。
func (s *Service) CountOneTimePreKeys(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM one_time_prekeys WHERE user_id = $1::uuid`, userID).Scan(&n)
	return n, err
}

// HasKeys 判断用户是否已发布密钥。
func (s *Service) HasKeys(ctx context.Context, userID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM device_identities WHERE user_id = $1::uuid)`, userID).Scan(&exists)
	return exists, err
}
