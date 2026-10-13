// Package validate 提供请求参数的轻量校验工具。
package validate

import (
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// UUID 判断字符串是否为合法的 UUID 文本。
// 在交给数据库做 ::uuid 转换之前先校验,避免非法输入变成 500 错误。
func UUID(s string) bool { return uuidRe.MatchString(s) }

// UUIDParams 返回一个中间件:若路由中出现所列路径参数且其值不是合法 UUID,直接返回 404。
func UUIDParams(names ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, n := range names {
			if v, ok := c.Params.Get(n); ok && !UUID(v) {
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "资源不存在"})
				return
			}
		}
		c.Next()
	}
}
