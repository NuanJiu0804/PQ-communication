// 基于后量子混合密码的端到端加密即时通讯系统 —— 后端服务入口。
//
// 职责边界:本服务只做认证、密钥分发、密文中继/暂存、媒体签发与元数据统计,
// 永远不持有用户私钥、不存储任何消息明文。E2EE 全部在客户端完成。
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/redis/go-redis/v9"

	"github.com/pqchat/server/internal/admin"
	"github.com/pqchat/server/internal/api"
	"github.com/pqchat/server/internal/auth"
	"github.com/pqchat/server/internal/buildinfo"
	"github.com/pqchat/server/internal/config"
	"github.com/pqchat/server/internal/database"
	"github.com/pqchat/server/internal/groups"
	"github.com/pqchat/server/internal/keys"
	"github.com/pqchat/server/internal/logging"
	"github.com/pqchat/server/internal/mailer"
	"github.com/pqchat/server/internal/media"
	"github.com/pqchat/server/internal/messaging"
	"github.com/pqchat/server/internal/social"
	"github.com/pqchat/server/internal/store"
	"github.com/pqchat/server/internal/token"
)

func main() {
	if err := run(); err != nil {
		// 此时日志器可能尚未初始化,直接写 stderr
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := logging.New(cfg.App.LogLevel)
	slog.SetDefault(logger)
	logger.Info("服务启动中",
		"service", cfg.App.Name,
		"version", buildinfo.Version,
		"env", cfg.App.Env,
	)

	ctx := context.Background()

	// ---- 连接数据存储(带重试,适配 docker-compose 启动竞态)----
	pg, err := connectPostgres(ctx, cfg, logger)
	if err != nil {
		return fmt.Errorf("连接 PostgreSQL: %w", err)
	}
	defer pg.Close()

	rdb, err := connectRedis(ctx, cfg, logger)
	if err != nil {
		return fmt.Errorf("连接 Redis: %w", err)
	}
	defer func() { _ = rdb.Close() }()

	// MinIO 仅服务媒体功能(P5);启动时连不上不致命,告警继续,/readyz 会如实标记 down。
	mc, err := connectMinIO(ctx, cfg, logger)
	if err != nil {
		logger.Warn("MinIO 暂不可用,媒体相关功能将不可用(认证/消息中继不受影响)", "error", err.Error())
		mc = nil
	}

	// ---- 数据库迁移 ----
	if cfg.App.RunMigrations {
		logger.Info("执行数据库迁移")
		if err := database.Migrate(cfg.Postgres.MigrateURL()); err != nil {
			return fmt.Errorf("数据库迁移: %w", err)
		}
		logger.Info("数据库迁移完成")
	}

	// ---- 装配账号与 E2EE 服务 ----
	mailClient := mailer.New(cfg.SMTP)
	tokenManager := token.NewManager(cfg.JWT.Secret, cfg.JWT.AccessTTL)
	authService := auth.NewService(pg, rdb, mailClient, tokenManager, logger, cfg)
	keysService := keys.NewService(pg)
	messagingHub := messaging.NewHub(messaging.NewRepo(pg), logger)
	socialService := social.NewService(pg)
	groupsService := groups.NewService(pg)
	mediaService := media.NewService(mc, cfg.MinIO.Bucket, pg)
	adminService := admin.NewService(pg, messagingHub)
	if err := adminService.EnsureSeedAdmin(ctx, cfg.Admin.Username, cfg.Admin.Password); err != nil {
		logger.Warn("初始化管理员账号失败", "error", err.Error())
	}

	// ---- 启动 HTTP 服务 ----
	srv := api.New(cfg, api.Deps{
		Logger:  logger,
		PG:      pg,
		Redis:   rdb,
		MinIO:   mc,
		Bucket:  cfg.MinIO.Bucket,
		AppName: cfg.App.Name,
		Version: buildinfo.Version,
		Auth:    authService,
		Tokens:  tokenManager,
		Keys:    keysService,
		Hub:     messagingHub,
		Social:  socialService,
		Groups:  groupsService,
		Media:   mediaService,
		Admin:   adminService,
	})

	serverErr := make(chan error, 1)
	go func() {
		if cfg.HTTP.TLS.Enabled {
			logger.Info("HTTPS 服务已监听(TLS 1.3 + 混合后量子 X25519MLKEM768)",
				"addr", cfg.HTTP.Addr, "cert", cfg.HTTP.TLS.CertFile)
			if err := srv.ListenAndServeTLS(cfg.HTTP.TLS.CertFile, cfg.HTTP.TLS.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverErr <- err
			}
			return
		}
		logger.Info("HTTP 服务已监听", "addr", cfg.HTTP.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// ---- 等待退出信号或服务异常 ----
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		return fmt.Errorf("HTTP 服务异常: %w", err)
	case sig := <-stop:
		logger.Info("收到停止信号,开始优雅关闭", "signal", sig.String())
	}

	shutdownCtx, cancel := context.WithTimeout(ctx, cfg.HTTP.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("优雅关闭失败: %w", err)
	}
	logger.Info("服务已退出")
	return nil
}

// retry 在依赖未就绪时做有限次重试。
func retry(ctx context.Context, logger *slog.Logger, name string, attempts int, delay time.Duration, fn func(context.Context) error) error {
	var last error
	for i := 1; i <= attempts; i++ {
		if last = fn(ctx); last == nil {
			return nil
		}
		logger.Warn("依赖连接失败,准备重试",
			"dependency", name, "attempt", i, "max", attempts, "error", last.Error())
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return last
}

func connectPostgres(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*pgxpool.Pool, error) {
	var pool *pgxpool.Pool
	err := retry(ctx, logger, "postgres", 15, 2*time.Second, func(ctx context.Context) error {
		p, err := store.NewPostgres(ctx, cfg.Postgres.DSN())
		if err != nil {
			return err
		}
		pool = p
		return nil
	})
	return pool, err
}

func connectRedis(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*redis.Client, error) {
	var client *redis.Client
	err := retry(ctx, logger, "redis", 15, 2*time.Second, func(ctx context.Context) error {
		c, err := store.NewRedis(ctx, cfg.Redis.Addr(), cfg.Redis.Password, cfg.Redis.DB)
		if err != nil {
			return err
		}
		client = c
		return nil
	})
	return client, err
}

func connectMinIO(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*minio.Client, error) {
	var client *minio.Client
	err := retry(ctx, logger, "minio", 3, 2*time.Second, func(ctx context.Context) error {
		c, err := store.NewMinIO(ctx, cfg.MinIO.Endpoint, cfg.MinIO.AccessKey, cfg.MinIO.SecretKey, cfg.MinIO.Bucket, cfg.MinIO.UseSSL)
		if err != nil {
			return err
		}
		client = c
		return nil
	})
	return client, err
}
