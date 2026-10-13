package keys

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pqchat/server/internal/auth"
)

// Handler 密钥分发相关的 HTTP 处理器。
type Handler struct {
	svc *Service
}

// NewHandler 创建处理器。
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Upload POST /api/v1/keys/upload(需鉴权):上传本人的身份与预密钥公钥。
func (h *Handler) Upload(c *gin.Context) {
	var req UploadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数有误", "detail": err.Error()})
		return
	}
	userID := c.GetString(auth.ContextUserID)
	if err := h.svc.Upload(c.Request.Context(), userID, &req); err != nil {
		if errors.Is(err, ErrInvalidKeys) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "上传密钥失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "密钥已上传"})
}

// FetchBundle GET /api/v1/keys/bundle/:userId(需鉴权):领取目标用户的预密钥包。
func (h *Handler) FetchBundle(c *gin.Context) {
	targetID := c.Param("userId")
	if targetID == c.GetString(auth.ContextUserID) {
		// 领取自己的预密钥包没有意义,还会白白消耗一次性预密钥
		c.JSON(http.StatusBadRequest, gin.H{"error": "不能领取自己的预密钥包"})
		return
	}
	bundle, err := h.svc.FetchBundle(c.Request.Context(), targetID)
	if err != nil {
		if errors.Is(err, ErrNoKeys) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取预密钥包失败"})
		return
	}
	c.JSON(http.StatusOK, bundle)
}

// Count GET /api/v1/keys/count(需鉴权):查询本人剩余一次性预密钥数量。
func (h *Handler) Count(c *gin.Context) {
	userID := c.GetString(auth.ContextUserID)
	n, err := h.svc.CountOneTimePreKeys(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"one_time_prekeys": n})
}
