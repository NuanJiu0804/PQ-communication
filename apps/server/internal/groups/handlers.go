package groups

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pqchat/server/internal/auth"
	"github.com/pqchat/server/internal/validate"
)

// Handler 群组的 HTTP 处理器。
type Handler struct {
	svc *Service
}

// NewHandler 创建处理器。
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

func self(c *gin.Context) string { return c.GetString(auth.ContextUserID) }

// Create POST /api/v1/groups
func (h *Handler) Create(c *gin.Context) {
	var req struct {
		Name      string   `json:"name" binding:"required,min=1,max=64"`
		MemberIDs []string `json:"member_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数有误", "detail": err.Error()})
		return
	}
	if len(req.MemberIDs) > maxGroupMembers {
		writeErr(c, ErrBadRequest)
		return
	}
	for _, id := range req.MemberIDs {
		if !validate.UUID(id) {
			writeErr(c, ErrBadRequest)
			return
		}
	}
	g, err := h.svc.CreateGroup(c.Request.Context(), self(c), req.Name, req.MemberIDs)
	if err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusCreated, g)
}

// List GET /api/v1/groups
func (h *Handler) List(c *gin.Context) {
	gs, err := h.svc.ListGroups(c.Request.Context(), self(c))
	if err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"groups": gs})
}

// Get GET /api/v1/groups/:groupId
func (h *Handler) Get(c *gin.Context) {
	d, err := h.svc.GetGroup(c.Request.Context(), self(c), c.Param("groupId"))
	if err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, d)
}

// Members GET /api/v1/groups/:groupId/members
func (h *Handler) Members(c *gin.Context) {
	ms, err := h.svc.Members(c.Request.Context(), self(c), c.Param("groupId"))
	if err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"members": ms})
}

// AddMember POST /api/v1/groups/:groupId/members
func (h *Handler) AddMember(c *gin.Context) {
	var req struct {
		UserID string `json:"user_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数有误", "detail": err.Error()})
		return
	}
	if !validate.UUID(req.UserID) {
		writeErr(c, ErrUserNotFound)
		return
	}
	if err := h.svc.AddMember(c.Request.Context(), self(c), c.Param("groupId"), req.UserID); err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "已加入群成员"})
}

// RemoveMember DELETE /api/v1/groups/:groupId/members/:userId
func (h *Handler) RemoveMember(c *gin.Context) {
	if err := h.svc.RemoveMember(c.Request.Context(), self(c), c.Param("groupId"), c.Param("userId")); err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "已移除成员"})
}

// Leave POST /api/v1/groups/:groupId/leave
func (h *Handler) Leave(c *gin.Context) {
	if err := h.svc.Leave(c.Request.Context(), self(c), c.Param("groupId")); err != nil {
		writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "已退出群组"})
}

// Register 在已鉴权的 v1 组上注册群组路由。
func (h *Handler) Register(v1 *gin.RouterGroup) {
	v1.POST("/groups", h.Create)
	v1.GET("/groups", h.List)
	v1.GET("/groups/:groupId", h.Get)
	v1.GET("/groups/:groupId/members", h.Members)
	v1.POST("/groups/:groupId/members", h.AddMember)
	v1.DELETE("/groups/:groupId/members/:userId", h.RemoveMember)
	v1.POST("/groups/:groupId/leave", h.Leave)
}

func writeErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrUserNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, ErrNotMember), errors.Is(err, ErrNotOwner):
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	case errors.Is(err, ErrBadRequest):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器内部错误"})
	}
}
