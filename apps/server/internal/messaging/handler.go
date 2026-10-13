package messaging

import (
	"net/http"

	"github.com/coder/websocket"
	"github.com/gin-gonic/gin"

	"github.com/pqchat/server/internal/token"
	"github.com/pqchat/server/internal/validate"
)

// Handler 负责 WebSocket 升级与鉴权。
type Handler struct {
	hub    *Hub
	tokens *token.Manager
}

// NewHandler 创建 WS 处理器。
func NewHandler(hub *Hub, tokens *token.Manager) *Handler {
	return &Handler{hub: hub, tokens: tokens}
}

// ServeWS GET /api/v1/ws?token=<access>:升级为 WebSocket 并接入中继。
// 浏览器 WebSocket 无法设置 Authorization 头,故访问令牌通过查询参数传入。
func (h *Handler) ServeWS(c *gin.Context) {
	userID, err := h.tokens.ParseAccess(c.Query("token"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的访问令牌"})
		return
	}
	// 访问令牌在有效期内无法撤销,这里额外拒绝已封禁账号接入实时中继
	if banned, err := h.hub.repo.IsBanned(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器内部错误"})
		return
	} else if banned {
		c.JSON(http.StatusForbidden, gin.H{"error": "账号已被封禁"})
		return
	}

	conn, err := websocket.Accept(c.Writer, c.Request, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"}, // 开发期允许浏览器预览与 Tauri webview 跨源连接
	})
	if err != nil {
		return
	}
	defer conn.CloseNow()

	h.hub.Serve(c.Request.Context(), userID, conn)
	_ = conn.Close(websocket.StatusNormalClosure, "")
}

// Presence GET /api/v1/presence/:userId(需鉴权):查询目标用户是否在线。
// 存在拉黑关系时一律显示离线,不泄露对方在线状态。
func (h *Handler) Presence(c *gin.Context) {
	target := c.Param("userId")
	if !validate.UUID(target) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的用户 ID"})
		return
	}
	self := c.GetString("user_id")
	if blocked, err := h.hub.repo.IsBlocked(c.Request.Context(), self, target); err != nil || blocked {
		c.JSON(http.StatusOK, gin.H{"online": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{"online": h.hub.IsOnline(target)})
}
