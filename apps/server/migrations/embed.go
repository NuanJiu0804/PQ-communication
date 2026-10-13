// Package migrations 以内嵌方式提供 SQL 迁移文件,使后端二进制自带迁移能力,
// 在 Windows 与 Ubuntu 上行为一致,无需额外分发迁移脚本。
package migrations

import "embed"

// FS 内嵌当前目录下的全部 .sql 迁移文件。
//
//go:embed *.sql
var FS embed.FS
