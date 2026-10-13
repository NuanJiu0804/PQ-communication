package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/pqchat/server/internal/token"
)

// SessionRevoker 吊销用户全部登录会话(由账号服务提供)。
type SessionRevoker interface {
	RevokeAllSessions(ctx context.Context, userID string) error
}

// 管理员登录失败限速:同一用户名或同一 IP 在窗口期内失败过多即暂时拒绝,防止口令爆破。
const (
	adminLoginFailLimit  = 5
	adminLoginFailWindow = 15 * time.Minute
)

type loginLimiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

func (l *loginLimiter) recent(key string, now time.Time) []time.Time {
	kept := l.fails[key][:0]
	for _, t := range l.fails[key] {
		if now.Sub(t) < adminLoginFailWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.fails, key)
		return nil
	}
	l.fails[key] = kept
	return kept
}

func (l *loginLimiter) blocked(keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, k := range keys {
		if len(l.recent(k, now)) >= adminLoginFailLimit {
			return true
		}
	}
	return false
}

func (l *loginLimiter) fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, k := range keys {
		l.fails[k] = append(l.recent(k, now), now)
	}
}

func (l *loginLimiter) reset(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.fails, k)
	}
}

// ContextAdminID 管理员鉴权中间件写入的管理员 ID 键。
const ContextAdminID = "admin_id"

// Handler 管理后台的 HTTP 处理器。
type Handler struct {
	svc      *Service
	tokens   *token.Manager
	sessions SessionRevoker
	limiter  *loginLimiter
}

// NewHandler 创建处理器。
func NewHandler(svc *Service, tokens *token.Manager, sessions SessionRevoker) *Handler {
	return &Handler{
		svc:      svc,
		tokens:   tokens,
		sessions: sessions,
		limiter:  &loginLimiter{fails: make(map[string][]time.Time)},
	}
}

// requireAdmin 管理员鉴权中间件(独立于普通用户令牌)。
func (h *Handler) requireAdmin() gin.HandlerFunc {
	const prefix = "Bearer "
	return func(c *gin.Context) {
		authz := c.GetHeader("Authorization")
		if !strings.HasPrefix(authz, prefix) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "缺少管理员令牌"})
			return
		}
		adminID, err := h.tokens.ParseAdmin(strings.TrimPrefix(authz, prefix))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "管理员令牌无效或已过期"})
			return
		}
		c.Set(ContextAdminID, adminID)
		c.Next()
	}
}

// Login POST /api/v1/admin/login
func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数有误"})
		return
	}
	keys := []string{"user:" + req.Username, "ip:" + c.ClientIP()}
	if h.limiter.blocked(keys...) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "登录失败次数过多,请稍后再试"})
		return
	}
	adminID, role, err := h.svc.Login(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			h.limiter.fail(keys...)
			h.svc.Audit(c.Request.Context(), "", "admin_login_failed", req.Username, "", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器内部错误"})
		return
	}
	h.limiter.reset(keys...)
	tokenStr, exp, err := h.tokens.GenerateAdmin(adminID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "签发令牌失败"})
		return
	}
	h.svc.Audit(c.Request.Context(), adminID, "admin_login", "", "", c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"access_token": tokenStr, "expires_at": exp.Unix(), "role": role})
}

func intQuery(c *gin.Context, key string, def int) int {
	if v := c.Query(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// Stats GET /api/v1/admin/stats
func (h *Handler) Stats(c *gin.Context) {
	st, err := h.svc.Stats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取指标失败"})
		return
	}
	c.JSON(http.StatusOK, st)
}

// Messages GET /api/v1/admin/messages?limit=
func (h *Handler) Messages(c *gin.Context) {
	msgs, err := h.svc.RecentMessages(c.Request.Context(), intQuery(c, "limit", 50))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取消息元数据失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"messages": msgs})
}

// Users GET /api/v1/admin/users?limit=
func (h *Handler) Users(c *gin.Context) {
	users, err := h.svc.ListUsers(c.Request.Context(), intQuery(c, "limit", 100))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

// Ban POST /api/v1/admin/users/:id/ban
func (h *Handler) Ban(c *gin.Context) {
	h.setBanned(c, true, "ban_user")
}

// Unban POST /api/v1/admin/users/:id/unban
func (h *Handler) Unban(c *gin.Context) {
	h.setBanned(c, false, "unban_user")
}

func (h *Handler) setBanned(c *gin.Context, banned bool, action string) {
	id := c.Param("id")
	if err := h.svc.SetBanned(c.Request.Context(), id, banned); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "操作失败"})
		return
	}
	if banned {
		// 吊销刷新令牌,使其无法续期;已签发的短时访问令牌由 WS 接入检查与过期兜底
		if err := h.sessions.RevokeAllSessions(c.Request.Context(), id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "吊销登录会话失败"})
			return
		}
	}
	h.svc.Audit(c.Request.Context(), c.GetString(ContextAdminID), action, id, "", c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"message": "操作成功"})
}

// Audit GET /api/v1/admin/audit
func (h *Handler) Audit(c *gin.Context) {
	logs, err := h.svc.ListAudit(c.Request.Context(), intQuery(c, "limit", 100))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取审计日志失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"audit": logs})
}

// Register 注册管理后台路由。login 公开,其余需管理员鉴权。
func (h *Handler) Register(v1 *gin.RouterGroup) {
	v1.POST("/admin/login", h.Login)

	a := v1.Group("/admin", h.requireAdmin())
	a.GET("/stats", h.Stats)
	a.GET("/messages", h.Messages)
	a.GET("/users", h.Users)
	a.POST("/users/:id/ban", h.Ban)
	a.POST("/users/:id/unban", h.Unban)
	a.GET("/audit", h.Audit)
}
