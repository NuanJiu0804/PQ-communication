package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/pqchat/server/internal/token"
)

// ContextUserID 是鉴权中间件写入 gin.Context 的当前用户 ID 键。
const ContextUserID = "user_id"

// RequireAuth 解析 Authorization: Bearer <access_token>,校验通过后写入用户 ID。
func RequireAuth(tm *token.Manager) gin.HandlerFunc {
	const prefix = "Bearer "
	return func(c *gin.Context) {
		authz := c.GetHeader("Authorization")
		if !strings.HasPrefix(authz, prefix) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "缺少访问令牌"})
			return
		}
		userID, err := tm.ParseAccess(strings.TrimPrefix(authz, prefix))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "访问令牌无效或已过期"})
			return
		}
		c.Set(ContextUserID, userID)
		c.Next()
	}
}
