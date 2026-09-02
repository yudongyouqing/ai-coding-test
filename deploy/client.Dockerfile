# syntax=docker/dockerfile:1
# ---------- 构建阶段 ----------
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/fpclient ./cmd/client

# ---------- 运行阶段：一次性任务容器，同样 scratch + 非 root ----------
FROM scratch AS runtime
LABEL org.opencontainers.image.title="banner-fingerprint-client" \
      org.opencontainers.image.description="Banner fingerprint CLI client (run-once job)"
COPY --from=build /out/fpclient /fpclient
USER 65532:65532
# 数据文件由 compose 以只读 volume 挂载到 /data，不打入镜像。
ENTRYPOINT ["/fpclient"]
