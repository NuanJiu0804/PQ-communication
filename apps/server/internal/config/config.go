// Package config 负责从环境变量(开发环境额外读取 .env 文件)加载并校验全部运行配置。
// 所有敏感信息一律走环境变量,严禁硬编码。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config 聚合应用运行所需的全部配置。
type Config struct {
	App          App
	HTTP         HTTP
	Postgres     Postgres
	Redis        Redis
	MinIO        MinIO
	JWT          JWT
	SMTP         SMTP
	Verification Verification
	Admin        Admin
}

// App 应用级配置。
type App struct {
	Env           string // development / production
	Name          string
	LogLevel      string
	RunMigrations bool
}

// IsProduction 是否生产环境。
func (a App) IsProduction() bool { return a.Env == "production" }

// HTTP 服务配置。
type HTTP struct {
	Addr               string
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	ShutdownTimeout    time.Duration
	CORSAllowedOrigins []string
	TLS                TLS
}

// TLS 传输层安全配置。
// 启用后服务以 HTTPS(强制 TLS 1.3)提供,并优先协商**混合后量子**密钥交换
// X25519MLKEM768(经典 X25519 ‖ 后量子 ML-KEM-768),抗「先存后解(HNDL)」。
// 注意:这是传输层加固,与应用层 E2EE 是两道独立防线,叠加生效。
type TLS struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

// Postgres 数据库配置。
type Postgres struct {
	Host     string
	Port     int
	User     string
	Password string
	DB       string
	SSLMode  string
}

// Redis 缓存配置。
type Redis struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// MinIO 对象存储配置。
type MinIO struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
}

// JWT 账号会话鉴权配置(与 E2EE 密钥体系完全独立)。
type JWT struct {
	Secret     string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// SMTP 邮件发送配置(邮箱验证码)。
type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	FromName string
	UseSSL   bool
}

// Verification 邮箱验证码策略。
type Verification struct {
	CodeTTL      time.Duration
	SendInterval time.Duration
	MaxAttempts  int
}

// Admin 管理后台初始账号(启动时若该用户名不存在且配置了密码则创建)。
type Admin struct {
	Username string
	Password string
}

// DSN 返回 pgxpool 使用的连接串。
func (p Postgres) DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		p.User, p.Password, p.Host, p.Port, p.DB, p.SSLMode)
}

// MigrateURL 返回 golang-migrate(pgx/v5 驱动)使用的连接串。
func (p Postgres) MigrateURL() string {
	return fmt.Sprintf("pgx5://%s:%s@%s:%d/%s?sslmode=%s",
		p.User, p.Password, p.Host, p.Port, p.DB, p.SSLMode)
}

// Addr 返回 redis 连接地址。
func (r Redis) Addr() string { return fmt.Sprintf("%s:%d", r.Host, r.Port) }

// Load 加载配置:开发环境会尝试读取 .env(找不到不报错),随后从环境变量解析。
func Load() (*Config, error) {
	loadDotEnv() // best-effort:从当前目录向上查找并加载 .env(本地开发)

	cfg := &Config{
		App: App{
			Env:           getEnv("APP_ENV", "development"),
			Name:          getEnv("APP_NAME", "基于后量子混合密码的端到端加密即时通讯系统"),
			LogLevel:      getEnv("LOG_LEVEL", "info"),
			RunMigrations: getEnvBool("RUN_MIGRATIONS", true),
		},
		HTTP: HTTP{
			Addr:               getEnv("HTTP_ADDR", ":8080"),
			ReadTimeout:        getEnvDuration("HTTP_READ_TIMEOUT", 15*time.Second),
			WriteTimeout:       getEnvDuration("HTTP_WRITE_TIMEOUT", 15*time.Second),
			ShutdownTimeout:    getEnvDuration("HTTP_SHUTDOWN_TIMEOUT", 10*time.Second),
			CORSAllowedOrigins: getEnvCSV("CORS_ALLOWED_ORIGINS", []string{"*"}),
			TLS: TLS{
				Enabled:  getEnvBool("TLS_ENABLED", false),
				CertFile: getEnv("TLS_CERT_FILE", "certs/dev-cert.pem"),
				KeyFile:  getEnv("TLS_KEY_FILE", "certs/dev-key.pem"),
			},
		},
		Postgres: Postgres{
			Host:     getEnv("POSTGRES_HOST", "localhost"),
			Port:     getEnvInt("POSTGRES_PORT", 5432),
			User:     getEnv("POSTGRES_USER", "pqchat"),
			Password: getEnv("POSTGRES_PASSWORD", ""),
			DB:       getEnv("POSTGRES_DB", "pqchat"),
			SSLMode:  getEnv("POSTGRES_SSLMODE", "disable"),
		},
		Redis: Redis{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnvInt("REDIS_PORT", 6379),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvInt("REDIS_DB", 0),
		},
		MinIO: MinIO{
			Endpoint:  getEnv("MINIO_ENDPOINT", "localhost:9000"),
			AccessKey: getEnv("MINIO_ROOT_USER", ""),
			SecretKey: getEnv("MINIO_ROOT_PASSWORD", ""),
			Bucket:    getEnv("MINIO_BUCKET", "pqchat-media"),
			UseSSL:    getEnvBool("MINIO_USE_SSL", false),
		},
		JWT: JWT{
			Secret:     getEnv("JWT_SECRET", ""),
			AccessTTL:  getEnvDuration("JWT_ACCESS_TTL", 15*time.Minute),
			RefreshTTL: getEnvDuration("JWT_REFRESH_TTL", 720*time.Hour),
		},
		SMTP: SMTP{
			Host:     getEnv("SMTP_HOST", ""),
			Port:     getEnvInt("SMTP_PORT", 465),
			Username: getEnv("SMTP_USERNAME", ""),
			Password: getEnv("SMTP_PASSWORD", ""),
			From:     getEnv("SMTP_FROM", ""),
			FromName: getEnv("SMTP_FROM_NAME", "基于后量子混合密码的端到端加密即时通讯系统"),
			UseSSL:   getEnvBool("SMTP_USE_SSL", true),
		},
		Verification: Verification{
			CodeTTL:      getEnvDuration("VERIFICATION_CODE_TTL", 10*time.Minute),
			SendInterval: getEnvDuration("VERIFICATION_SEND_INTERVAL", 60*time.Second),
			MaxAttempts:  getEnvInt("VERIFICATION_MAX_ATTEMPTS", 5),
		},
		Admin: Admin{
			Username: getEnv("ADMIN_USERNAME", "admin"),
			Password: getEnv("ADMIN_PASSWORD", ""),
		},
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validate 校验当前阶段必需的配置项。
func (c *Config) validate() error {
	var missing []string
	if c.Postgres.Password == "" {
		missing = append(missing, "POSTGRES_PASSWORD")
	}
	if c.MinIO.AccessKey == "" {
		missing = append(missing, "MINIO_ROOT_USER")
	}
	if c.MinIO.SecretKey == "" {
		missing = append(missing, "MINIO_ROOT_PASSWORD")
	}
	if c.JWT.Secret == "" {
		missing = append(missing, "JWT_SECRET")
	}
	if len(missing) > 0 {
		return fmt.Errorf("缺少必需的环境变量: %s(请参考 .env.example)", strings.Join(missing, ", "))
	}
	if c.App.IsProduction() && len(c.JWT.Secret) < 32 {
		return fmt.Errorf("生产环境 JWT_SECRET 至少需要 32 字节随机串")
	}
	return nil
}

// loadDotEnv 从当前工作目录开始,向上逐级(最多 5 层)查找 .env 并加载。
// 这样无论从仓库根还是 apps/server 子目录运行,都能读到同一份 .env。
// 找不到不报错:容器/生产环境直接用进程环境变量。
func loadDotEnv() {
	dir, err := os.Getwd()
	if err != nil {
		return
	}
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, ".env")
		if _, statErr := os.Stat(candidate); statErr == nil {
			_ = godotenv.Load(candidate)
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}
		dir = parent
	}
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func getEnvDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// getEnvCSV 解析逗号分隔的字符串列表。
func getEnvCSV(key string, def []string) []string {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}
