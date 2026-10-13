// 命令 initdb:本机原生开发(无 Docker)时的一次性数据库引导。
//
// 它连接到 PostgreSQL 的 postgres 维护库(该库总是存在),
// 若目标应用库(.env 中的 POSTGRES_DB)不存在则创建之。
// 表结构由后端启动时的迁移负责,这里只负责"建库"这一步。
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pqchat/server/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "initdb 失败: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 连接到 postgres 维护库,用于创建目标应用库
	maintDSN := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=%s",
		cfg.Postgres.User, cfg.Postgres.Password, cfg.Postgres.Host, cfg.Postgres.Port, cfg.Postgres.SSLMode)

	conn, err := pgx.Connect(ctx, maintDSN)
	if err != nil {
		return fmt.Errorf("连接 postgres 维护库: %w", err)
	}
	defer conn.Close(ctx)

	var exists bool
	if err := conn.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", cfg.Postgres.DB,
	).Scan(&exists); err != nil {
		return fmt.Errorf("查询数据库是否存在: %w", err)
	}

	if exists {
		fmt.Printf("数据库 %q 已存在,无需创建\n", cfg.Postgres.DB)
		return nil
	}

	// CREATE DATABASE 不能参数化库名,使用标识符转义避免注入
	stmt := "CREATE DATABASE " + pgx.Identifier{cfg.Postgres.DB}.Sanitize()
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("创建数据库 %q: %w", cfg.Postgres.DB, err)
	}
	fmt.Printf("已创建数据库 %q\n", cfg.Postgres.DB)
	return nil
}
