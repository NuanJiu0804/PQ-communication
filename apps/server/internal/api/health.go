package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// handler 持有 HTTP 处理所需依赖。
type handler struct {
	deps Deps
}

// healthz 存活探针:进程在运行即返回 200。
func (h *handler) healthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": h.deps.AppName,
		"version": h.deps.Version,
	})
}

// readyz 就绪探针:依次检查 PostgreSQL / Redis / MinIO,任一不可用则返回 503。
func (h *handler) readyz(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	checks := make(map[string]string, 3)
	healthy := true

	if err := h.deps.PG.Ping(ctx); err != nil {
		checks["postgres"] = "down: " + err.Error()
		healthy = false
	} else {
		checks["postgres"] = "up"
	}

	if err := h.deps.Redis.Ping(ctx).Err(); err != nil {
		checks["redis"] = "down: " + err.Error()
		healthy = false
	} else {
		checks["redis"] = "up"
	}

	if h.deps.MinIO == nil {
		checks["minio"] = "down: 未连接(媒体功能不可用)"
		healthy = false
	} else if _, err := h.deps.MinIO.BucketExists(ctx, h.deps.Bucket); err != nil {
		checks["minio"] = "down: " + err.Error()
		healthy = false
	} else {
		checks["minio"] = "up"
	}

	status := http.StatusOK
	statusText := "ok"
	if !healthy {
		status = http.StatusServiceUnavailable
		statusText = "degraded"
	}
	c.JSON(status, gin.H{
		"status": statusText,
		"checks": checks,
	})
}
