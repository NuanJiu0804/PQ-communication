package social

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pqchat/server/internal/auth"
	"github.com/pqchat/server/internal/validate"
)

// Handler 社交关系的 HTTP 处理器。
type Handler struct {
	svc *Service
}

// NewHandler 创建处理器。
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

func self(c *gin.Context) string { return c.GetString(auth.ContextUserID) }

// GetUser GET /api/v1/users/:userId
func (h *Handler) GetUser(c *gin.Context) {
	p, err := h.svc.GetProfile(c.Request.Context(), c.Param("userId"))
	if err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, p)
}

// SearchUser GET /api/v1/users/search?email=
func (h *Handler) SearchUser(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供 email 查询参数"})
		return
	}
	p, err := h.svc.SearchByEmail(c.Request.Context(), email)
	if err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, p)
}

// UpdateProfile PATCH /api/v1/me/profile
func (h *Handler) UpdateProfile(c *gin.Context) {
	var req struct {
		Nickname   *string `json:"nickname" binding:"omitempty,min=1,max=32"`
		AvatarURL  *string `json:"avatar_url" binding:"omitempty,max=512"`
		StatusText *string `json:"status_text" binding:"omitempty,max=140"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数有误", "detail": err.Error()})
		return
	}
	p, err := h.svc.UpdateProfile(c.Request.Context(), self(c), req.Nickname, req.AvatarURL, req.StatusText)
	if err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, p)
}

// SendRequest POST /api/v1/friends/requests
func (h *Handler) SendRequest(c *gin.Context) {
	var req struct {
		ToUserID string `json:"to_user_id" binding:"required"`
		Note     string `json:"note" binding:"max=140"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数有误", "detail": err.Error()})
		return
	}
	if !validate.UUID(req.ToUserID) {
		writeErr(c, ErrNotFound)
		return
	}
	auto, err := h.svc.SendRequest(c.Request.Context(), self(c), req.ToUserID, req.Note)
	if err != nil {
		writeErr(c, err)
		return
	}
	if auto {
		c.JSON(http.StatusOK, gin.H{"message": "对方此前已申请,已互加为好友", "auto_accepted": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "好友申请已发送", "auto_accepted": false})
}

// ListRequests GET /api/v1/friends/requests
func (h *Handler) ListRequests(c *gin.Context) {
	incoming, outgoing, err := h.svc.ListRequests(c.Request.Context(), self(c))
	if err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"incoming": incoming, "outgoing": outgoing})
}

// AcceptRequest POST /api/v1/friends/requests/:id/accept
func (h *Handler) AcceptRequest(c *gin.Context) {
	if err := h.svc.AcceptRequest(c.Request.Context(), self(c), c.Param("id")); err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "已添加为好友"})
}

// RejectRequest POST /api/v1/friends/requests/:id/reject
func (h *Handler) RejectRequest(c *gin.Context) {
	if err := h.svc.RejectRequest(c.Request.Context(), self(c), c.Param("id")); err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "已拒绝"})
}

// ListFriends GET /api/v1/friends
func (h *Handler) ListFriends(c *gin.Context) {
	friends, err := h.svc.ListFriends(c.Request.Context(), self(c))
	if err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"friends": friends})
}

// RemoveFriend DELETE /api/v1/friends/:userId
func (h *Handler) RemoveFriend(c *gin.Context) {
	if err := h.svc.RemoveFriend(c.Request.Context(), self(c), c.Param("userId")); err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "已删除好友"})
}

// Block POST /api/v1/blocks/:userId
func (h *Handler) Block(c *gin.Context) {
	if err := h.svc.Block(c.Request.Context(), self(c), c.Param("userId")); err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "已加入黑名单"})
}

// Unblock DELETE /api/v1/blocks/:userId
func (h *Handler) Unblock(c *gin.Context) {
	if err := h.svc.Unblock(c.Request.Context(), self(c), c.Param("userId")); err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "已移出黑名单"})
}

// ListBlocks GET /api/v1/blocks
func (h *Handler) ListBlocks(c *gin.Context) {
	blocks, err := h.svc.ListBlocks(c.Request.Context(), self(c))
	if err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"blocks": blocks})
}

// Register 在已鉴权的 v1 组上注册社交路由。
// 注意:gin 不允许同一段同时存在静态路由与参数路由,故 search/requests 用独立前缀。
func (h *Handler) Register(v1 *gin.RouterGroup) {
	v1.GET("/search/users", h.SearchUser)
	v1.GET("/users/:userId", h.GetUser)
	v1.PATCH("/me/profile", h.UpdateProfile)

	v1.GET("/friends", h.ListFriends)
	v1.DELETE("/friends/:userId", h.RemoveFriend)

	v1.POST("/friend-requests", h.SendRequest)
	v1.GET("/friend-requests", h.ListRequests)
	v1.POST("/friend-requests/:id/accept", h.AcceptRequest)
	v1.POST("/friend-requests/:id/reject", h.RejectRequest)

	v1.GET("/blocks", h.ListBlocks)
	v1.POST("/blocks/:userId", h.Block)
	v1.DELETE("/blocks/:userId", h.Unblock)
}

func writeErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrRequestNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, ErrSelf):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, ErrBlocked):
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	case errors.Is(err, ErrAlreadyFriends), errors.Is(err, ErrRequestExists):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器内部错误"})
	}
}
