# Banner 指纹识别系统

Golang 实现的 client + server 架构 Banner 指纹识别系统：接收一批网络扫描原始数据（`ip` / `port` / `banner`），识别出协议、软件与版本信息。**识别规则以数据文件形式与程序代码完全解耦**，可通过 volume 热替换，无需重新编译。零第三方依赖（纯 Go 标准库），Docker Compose 一键启动。

## 架构

```
┌─────────────┐  HTTP POST /fingerprint   ┌──────────────────┐
│   client    │ ────────────────────────► │      server      │
│ 读本地 JSON  │   [{ip,port,banner},...]  │  规则引擎(RE2)    │
│ 表格化输出   │ ◄──────────────────────── │  rules.json(挂载) │
└─────────────┘   [{protocol,product,     └──────────────────┘
                   version,os_hint,
                   confidence},...]
```

- **client**（`cmd/client`）：读取本地 JSON 文件（默认 `testdata/input.json`），POST 给 server，`tabwriter` 对齐表格展示 + 协议汇总统计，可选 `-output` 落盘 JSON。带指数退避重试。
- **server**（`cmd/server`）：`POST /fingerprint` 批量识别 + `GET /health` 健康检查。规则加载失败 fail-fast，识别失败降级为 `unknown`，永不因单条脏数据崩溃。
- **规则**（`rules/rules.json`）：RE2 正则 + 命名捕获组，声明式描述协议/产品/版本/OS 提取方式与置信度。

## 一键启动（Docker Compose）

```bash
docker compose up --build
```

- `server` 长驻，健康后对外提供 `http://localhost:8080`
- `client` 等 server **健康检查通过后**自动运行一次，读取挂载的 `./testdata/input.json` 并在标准输出打印识别表格，然后退出（`restart: "no"` 的 run-once 任务容器）

换一批数据再跑：

```bash
cp your-data.json testdata/input.json
docker compose run --rm client            # 复用已 healthy 的 server
```

直接调 API：

```bash
curl -s localhost:8080/health
curl -s -X POST localhost:8080/fingerprint -H 'Content-Type: application/json' --data-binary @testdata/input.json
```

## API

### `POST /fingerprint`

请求体为记录数组（也兼容 `{"records":[...]}` 包装）：

```json
[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]
```

响应为逐条识别结果（顺序与输入一致，认不出的条目返回 `protocol:"unknown"`、`confidence:0`，不会报错）：

```json
[{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}]
```

错误处理：非法 JSON → 400；超过 32MB → 413；方法不对 → 405；handler panic 被中间件兜住转 500，进程不退出。

### `GET /health`

```json
{"status":"ok","rules":28,"timestamp":"2026-09-02T00:00:00Z"}
```

## 识别能力

| 协议 | 可识别产品（示例） | 版本 | OS 提示来源 |
|---|---|---|---|
| SSH | OpenSSH、Dropbear、libssh 等通用 | ✅ | `Ubuntu-3`、`Debian-1` 等发行版后缀 |
| HTTP | nginx、Apache、Jetty、Microsoft IIS、Tomcat、lighttpd，未知 `Server:` 头原样提取 | ✅ | `(Ubuntu)` 后缀；IIS 固定 Windows |
| MySQL | MySQL、MariaDB（握手包二进制解析，剥离 `5.5.5-` 兼容前缀） | ✅ | — |
| Redis | RESP 协议特征（`-ERR`/`+PONG`/`-NOAUTH`/bulk 响应） | — | — |
| FTP | ProFTPD、vsftpd、Pure-FTPd、Microsoft FTP Service | ✅ | Microsoft → Windows |
| 其他 | SMTP(Postfix/Exim)、POP3、IMAP、PostgreSQL、VNC、Telnet、SSL/TLS 握手 | 部分 | — |

**置信度语义**：规则基础置信度 +（banner 命中且端口吻合 → +0.02，上限 0.99），保留两位小数。多规则命中时按 `priority` > `confidence` 取最优。无规则命中但端口是知名端口 → 仅按端口猜测（confidence 0.3）；完全无法识别 → `unknown` / 0。

## 规则扩展（代码与规则解耦）

规则全部在 `rules/rules.json`，server 启动时编译加载；compose 中 `./rules` 以只读 volume 挂载到 `/etc/bannerfp`，**新增/修改规则只需改 JSON 并 `docker compose restart server`，无需重新构建镜像**。字段说明：

| 字段 | 说明 |
|---|---|
| `match` | RE2 正则；`(?P<version>...)` 命名组提取版本 |
| `protocol` / `product` | 固定输出值；`product_group` 可改为从命名组提取（如未知 `Server:` 头） |
| `os` / `os_regex` | 固定 OS 提示 / 从 banner 提取 OS 关键词（如 Ubuntu/Debian） |
| `ports` | 端口吻合时置信度 +0.02 |
| `priority` | 多规则命中的仲裁顺序（专用规则 > 通用规则） |
| `version_strip_prefix` | 版本串去前缀（MariaDB `5.5.5-`） |

新增协议示例：往 `rules` 数组追加一条即可，`$comment` 里有完整说明。

## 生产化部署要点

- **镜像**：多阶段构建（`golang:1.24-alpine` → `scratch`），`CGO_ENABLED=0` + `-trimpath -ldflags "-s -w"` 静态编译，运行镜像为空镜像 + 单二进制（约 5-8MB），无 shell、无包管理器、无攻击面。
- **权限收紧**：`USER 65532` 非 root；`read_only` 只读根文件系统；`cap_drop: [ALL]`；`no-new-privileges`；`pids_limit` / `mem_limit` 资源上限。
- **容器间访问收敛**：client 仅通过 compose 内部 bridge 网络以服务名访问 `http://server:8080`；server 端口发布到宿主机仅供调试，可整体删掉 `ports:` 不影响 client。
- **真实健康检测**：healthcheck 由二进制自身 `fpserver -selfcheck` 探活 `/health`（scratch 无 shell/wget，故内置于程序）；client `depends_on: condition: service_healthy`，杜绝启动竞态。
- **服务韧性**：请求体大小上限、完整 http.Server 超时（ReadHeader/Read/Write/Idle）、SIGTERM 优雅退出（10s 排水）、panic recovery 中间件、结构化访问日志。
- **规则与代码解耦**：见上节，规则是挂载进容器的数据文件。

## 本地开发（不依赖 Docker）

```bash
go test ./...                                   # 单测覆盖全部示例数据 + 边界/防崩溃用例
go run ./cmd/server &                           # 默认 :8080，规则默认 rules/rules.json
go run ./cmd/client -input testdata/input.json  # 识别并打印表格
ADDR=:9000 RULES_PATH=/path/to/rules.json go run ./cmd/server
```

## 目录结构

```
├── cmd/server/          # HTTP 服务入口
├── cmd/client/          # CLI 客户端入口
├── internal/engine/     # 识别引擎（规则加载/正则匹配/打分）+ 单测
├── internal/server/     # HTTP handler 与中间件
├── rules/rules.json     # 指纹规则库（数据驱动，与代码解耦）
├── testdata/input.json  # 自测样例数据（题目示例）
├── deploy/*.Dockerfile  # server / client 多阶段构建
└── docker-compose.yml   # 一键编排
```
