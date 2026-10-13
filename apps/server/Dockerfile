# syntax=docker/dockerfile:1

# ---- 构建阶段:完整 Go 工具链 ----
FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X github.com/pqchat/server/internal/buildinfo.Version=docker" \
    -o /out/server ./cmd/server

# ---- 运行阶段:精简镜像,非 root 运行 ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -u 10001 appuser
USER appuser
WORKDIR /app
COPY --from=build /out/server /app/server
EXPOSE 8080
ENTRYPOINT ["/app/server"]
