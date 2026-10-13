package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// corsMiddleware 处理跨域请求,使浏览器预览(:5173)与 Tauri webview 都能调用后端。
// 由于鉴权走 Authorization: Bearer(不用 Cookie),允许 "*" 也无凭据泄露风险。
func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	allowAll := false
	allowSet := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if o == "*" {
			allowAll = true
		}
		allowSet[o] = struct{}{}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			if allowAll {
				c.Header("Access-Control-Allow-Origin", "*")
			} else if _, ok := allowSet[origin]; ok {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
			}
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
			c.Header("Access-Control-Max-Age", "600")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
