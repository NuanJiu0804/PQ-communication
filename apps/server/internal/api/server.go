// Package api 组装 HTTP 路由与处理器。
package api

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/redis/go-redis/v9"

	"github.com/pqchat/server/internal/admin"
	"github.com/pqchat/server/internal/auth"
	"github.com/pqchat/server/internal/config"
	"github.com/pqchat/server/internal/groups"
	"github.com/pqchat/server/internal/keys"
	"github.com/pqchat/server/internal/media"
	"github.com/pqchat/server/internal/messaging"
	"github.com/pqchat/server/internal/social"
	"github.com/pqchat/server/internal/token"
	"github.com/pqchat/server/internal/validate"
)

// Deps 聚合 HTTP 层所需的依赖。
type Deps struct {
	Logger  *slog.Logger
	PG      *pgxpool.Pool
	Redis   *redis.Client
	MinIO   *minio.Client
	Bucket  string
	AppName string
	Version string
	Auth    *auth.Service
	Tokens  *token.Manager
	Keys    *keys.Service
	Hub     *messaging.Hub
	Social  *social.Service
	Groups  *groups.Service
	Media   *media.Service
	Admin   *admin.Service
}

// New 构造配置完成的 HTTP 服务器。
func New(cfg *config.Config, deps Deps) *http.Server {
	if cfg.App.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(requestLogger(deps.Logger))
	router.Use(corsMiddleware(cfg.HTTP.CORSAllowedOrigins))

	h := &handler{deps: deps}
	router.GET("/healthz", h.healthz)
	router.GET("/readyz", h.readyz)

	// 账号鉴权(与 E2EE 密钥体系独立)
	authH := auth.NewHandler(deps.Auth)
	v1 := router.Group("/api/v1", validate.UUIDParams("userId", "groupId", "id"))
	{
		ag := v1.Group("/auth")
		ag.POST("/register/send-code", authH.SendRegisterCode)
		ag.POST("/register", authH.Register)
		ag.POST("/login", authH.Login)
		ag.POST("/refresh", authH.Refresh)
		ag.POST("/logout", authH.Logout)

		v1.GET("/me", auth.RequireAuth(deps.Tokens), authH.Me)

		// E2EE 公钥分发(需鉴权)
		keysH := keys.NewHandler(deps.Keys)
		kg := v1.Group("/keys", auth.RequireAuth(deps.Tokens))
		kg.POST("/upload", keysH.Upload)
		kg.GET("/bundle/:userId", keysH.FetchBundle)
		kg.GET("/count", keysH.Count)

		// 密文消息实时中继(令牌经查询参数鉴权)
		msgH := messaging.NewHandler(deps.Hub, deps.Tokens)
		v1.GET("/ws", msgH.ServeWS)
		v1.GET("/presence/:userId", auth.RequireAuth(deps.Tokens), msgH.Presence)

		// 社交关系 + 群组,整组需鉴权
		authed := v1.Group("", auth.RequireAuth(deps.Tokens))
		social.NewHandler(deps.Social).Register(authed)
		groups.NewHandler(deps.Groups).Register(authed)
		media.NewHandler(deps.Media).Register(authed)

		// 管理后台(独立鉴权;login 公开,其余需管理员令牌)
		admin.NewHandler(deps.Admin, deps.Tokens, deps.Auth).Register(v1)
	}

	srv := &http.Server{
		Addr:         cfg.HTTP.Addr,
		Handler:      router,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
	}
	if cfg.HTTP.TLS.Enabled {
		srv.TLSConfig = pqTLSConfig()
	}
	return srv
}

// pqTLSConfig 返回启用混合后量子密钥交换的 TLS 配置。
//
//   - 强制 TLS 1.3:只有 1.3 才支持 X25519MLKEM768 这类后量子曲线。
//   - CurvePreferences 把 X25519MLKEM768(X25519 ‖ ML-KEM-768 混合)排在最前:
//     握手时只要对端支持就优先用它协商会话密钥;不支持则回退到经典 X25519。
//     由此,即便攻击者今天截获并存储握手流量,未来有了量子计算机也无法还原
//     会话密钥(抗 Harvest-Now-Decrypt-Later)。
//
// 证书的签名算法(ECDSA/Ed25519)与此无关——后量子加固在「密钥交换」环节,
// 而非证书签名;故用普通自签/CA 证书即可。
func pqTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, // 混合后量子(首选)
			tls.X25519,         // 经典回退
		},
	}
}

// requestLogger 是基于 slog 的访问日志中间件。
func requestLogger(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		logger.Info("http_request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"client_ip", c.ClientIP(),
		)
	}
}
