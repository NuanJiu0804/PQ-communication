package auth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler 账号相关的 HTTP 处理器。
type Handler struct {
	svc *Service
}

// NewHandler 创建处理器。
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// SendRegisterCode POST /api/v1/auth/register/send-code
func (h *Handler) SendRegisterCode(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if err := h.svc.SendRegisterCode(c.Request.Context(), req.Email); err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "验证码已发送"})
}

// Register POST /api/v1/auth/register
func (h *Handler) Register(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Code     string `json:"code" binding:"required,len=6"`
		Password string `json:"password" binding:"required,min=8,max=128"`
		Nickname string `json:"nickname" binding:"required,min=1,max=32"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	ua, ip := clientMeta(c)
	pair, err := h.svc.Register(c.Request.Context(), req.Email, req.Code, req.Password, req.Nickname, ua, ip)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusCreated, authResponse(pair))
}

// Login POST /api/v1/auth/login
func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	ua, ip := clientMeta(c)
	pair, err := h.svc.Login(c.Request.Context(), req.Email, req.Password, ua, ip)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, authResponse(pair))
}

// Refresh POST /api/v1/auth/refresh
func (h *Handler) Refresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	ua, ip := clientMeta(c)
	pair, err := h.svc.Refresh(c.Request.Context(), req.RefreshToken, ua, ip)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, authResponse(pair))
}

// Logout POST /api/v1/auth/logout
func (h *Handler) Logout(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if err := h.svc.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "已退出登录"})
}

// Me GET /api/v1/me(需鉴权)
func (h *Handler) Me(c *gin.Context) {
	userID := c.GetString(ContextUserID)
	user, err := h.svc.Me(c.Request.Context(), userID)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user})
}

// ---- 辅助 ----

func clientMeta(c *gin.Context) (userAgent, ip string) {
	return c.Request.UserAgent(), c.ClientIP()
}

func authResponse(pair *TokenPair) gin.H {
	return gin.H{
		"access_token":  pair.AccessToken,
		"refresh_token": pair.RefreshToken,
		"expires_at":    pair.ExpiresAt.Unix(),
		"user":          pair.User,
	}
}

func badRequest(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数有误", "detail": err.Error()})
}

// writeServiceError 将业务错误映射为 HTTP 状态码。
func writeServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrEmailTaken):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, ErrCodeInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, ErrRateLimited):
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
	case errors.Is(err, ErrInvalidCredentials), errors.Is(err, ErrInvalidRefresh):
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	case errors.Is(err, ErrAccountBanned):
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	case errors.Is(err, ErrSMTPRequired):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器内部错误"})
	}
}
