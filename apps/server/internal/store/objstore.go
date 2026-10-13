package store

import (
	"context"
	"fmt"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// NewMinIO 创建 MinIO 客户端并确保目标 bucket 存在。
// 注意:这里只创建 bucket,不读取任何对象内容;对象一律是客户端加密后的媒体密文。
func NewMinIO(ctx context.Context, endpoint, accessKey, secretKey, bucket string, useSSL bool) (*minio.Client, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, err
	}

	opCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	exists, err := client.BucketExists(opCtx, bucket)
	if err != nil {
		return nil, fmt.Errorf("检查 bucket %q: %w", bucket, err)
	}
	if !exists {
		if err := client.MakeBucket(opCtx, bucket, minio.MakeBucketOptions{}); err != nil {
			return nil, fmt.Errorf("创建 bucket %q: %w", bucket, err)
		}
	}
	return client, nil
}
