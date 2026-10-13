// Package logging 提供基于标准库 log/slog 的结构化日志器。
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New 按日志级别名称创建 JSON 结构化日志器(输出到 stdout)。
func New(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv})
	return slog.New(handler)
}
