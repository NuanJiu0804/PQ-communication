// Package media 通过 MinIO 预签名 URL 收发客户端加密后的媒体密文。
// 服务器只签发上传/下载 URL 并记录元数据;对象内容为密文,服务器无法解密。
package media

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
)

// ErrUnavailable 对象存储不可用(MinIO 未连接)。
var ErrUnavailable = errors.New("媒体存储暂不可用")

// ErrInvalid 请求参数不合法(大小越界、对象键格式错误等)。
var ErrInvalid = errors.New("媒体参数不合法")

// MaxObjectBytes 单个媒体密文对象的大小上限(客户端明文上限 20 MB,另含 AEAD 标签)。
const MaxObjectBytes = 25 * 1024 * 1024

// objectKeyRe 服务器生成的对象键格式:media/<32 位十六进制>。
var objectKeyRe = regexp.MustCompile(`^media/[0-9a-f]{32}$`)

// Service 媒体服务。
type Service struct {
	minio  *minio.Client
	bucket string
	pool   *pgxpool.Pool
	expiry time.Duration
}

// NewService 创建媒体服务。minio 可能为 nil(MinIO 未连接)。
func NewService(mc *minio.Client, bucket string, pool *pgxpool.Pool) *Service {
	return &Service{minio: mc, bucket: bucket, pool: pool, expiry: 15 * time.Minute}
}

// Available 媒体存储是否可用。
func (s *Service) Available() bool { return s.minio != nil }

// CreateUpload 生成对象键与预签名 PUT URL,并登记元数据。
func (s *Service) CreateUpload(ctx context.Context, uploaderID, contentType string, size int64) (objectKey, uploadURL string, err error) {
	if s.minio == nil {
		return "", "", ErrUnavailable
	}
	if size <= 0 || size > MaxObjectBytes {
		return "", "", ErrInvalid
	}
	objectKey = "media/" + randomKey()
	u, err := s.minio.PresignedPutObject(ctx, s.bucket, objectKey, s.expiry)
	if err != nil {
		return "", "", err
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO media_objects (object_key, uploader_id, content_type, size)
		 VALUES ($1, $2::uuid, $3, $4)`,
		objectKey, uploaderID, contentType, size); err != nil {
		return "", "", err
	}
	return objectKey, u.String(), nil
}

// DownloadURL 为已知对象键生成预签名 GET URL。
func (s *Service) DownloadURL(ctx context.Context, objectKey string) (string, error) {
	if s.minio == nil {
		return "", ErrUnavailable
	}
	if !objectKeyRe.MatchString(objectKey) {
		return "", ErrInvalid
	}
	u, err := s.minio.PresignedGetObject(ctx, s.bucket, objectKey, s.expiry, nil)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func randomKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
