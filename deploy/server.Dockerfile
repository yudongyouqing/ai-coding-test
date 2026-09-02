# syntax=docker/dockerfile:1
# ---------- 构建阶段：静态编译，产出无依赖的 Go 二进制 ----------
FROM golang:1.24-alpine AS build
WORKDIR /src
# 先拷 go.mod 利用层缓存（本项目零第三方依赖，download 为空操作但保留标准姿势）
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/fpserver ./cmd/server

# ---------- 运行阶段：scratch（空镜像）+ 非 root ----------
# 静态二进制 + 运行时挂载的 JSON 规则 = 不需要任何基础系统。
FROM scratch AS runtime
LABEL org.opencontainers.image.title="banner-fingerprint-server" \
      org.opencontainers.image.description="Banner fingerprint identification HTTP server"
COPY --from=build /out/fpserver /fpserver
# 镜像内自带一份默认规则兜底；compose 实际通过 volume 用 ./rules 覆盖，实现规则热替换。
COPY --from=build /src/rules/rules.json /etc/bannerfp/rules.json
ENV ADDR=:8080 \
    RULES_PATH=/etc/bannerfp/rules.json
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/fpserver"]
