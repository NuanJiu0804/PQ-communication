// Package database 负责执行内嵌的数据库迁移。
package database

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	// 注册 pgx/v5 数据库驱动(连接串 scheme: pgx5://)
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/pqchat/server/migrations"
)

// Migrate 使用内嵌的 SQL 迁移文件,将数据库升级到最新版本。
// databaseURL 形如 pgx5://user:pass@host:port/db?sslmode=disable。
func Migrate(databaseURL string) error {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("加载内嵌迁移文件: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, databaseURL)
	if err != nil {
		return fmt.Errorf("初始化迁移器: %w", err)
	}
	defer func() {
		srcErr, dbErr := m.Close()
		_ = srcErr
		_ = dbErr
	}()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}
