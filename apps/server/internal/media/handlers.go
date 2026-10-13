package media

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pqchat/server/internal/auth"
)

// Handler 媒体的 HTTP 处理器。
type Handler struct {
	svc *Service
}

// NewHandler 创建处理器。
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// CreateUpload POST /api/v1/media/upload-url
func (h *Handler) CreateUpload(c *gin.Context) {
	var req struct {
		ContentType string `json:"content_type" binding:"max=128"`
		Size        int64  `json:"size"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数有误", "detail": err.Error()})
		return
	}
	userID := c.GetString(auth.ContextUserID)
	objectKey, uploadURL, err := h.svc.CreateUpload(c.Request.Context(), userID, req.ContentType, req.Size)
	if err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"object_key": objectKey, "upload_url": uploadURL})
}

// DownloadURL GET /api/v1/media/download-url?key=<objectKey>
func (h *Handler) DownloadURL(c *gin.Context) {
	key := c.Query("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 key 参数"})
		return
	}
	url, err := h.svc.DownloadURL(c.Request.Context(), key)
	if err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"download_url": url})
}

// Register 在已鉴权的 v1 组上注册媒体路由。
func (h *Handler) Register(v1 *gin.RouterGroup) {
	v1.POST("/media/upload-url", h.CreateUpload)
	v1.GET("/media/download-url", h.DownloadURL)
}

func writeErr(c *gin.Context, err error) {
	if errors.Is(err, ErrUnavailable) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	if errors.Is(err, ErrInvalid) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器内部错误"})
}
