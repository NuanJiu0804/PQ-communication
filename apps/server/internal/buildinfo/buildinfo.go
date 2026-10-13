// Package buildinfo 暴露构建期注入的版本信息。
package buildinfo

// Version 由构建参数 -ldflags "-X .../buildinfo.Version=..." 注入,默认 dev。
var Version = "dev"
