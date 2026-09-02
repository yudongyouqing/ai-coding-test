# Banner Fingerprint

A Go client/server system for identifying network service banners. The server accepts a batch of `{ip, port, banner}` records and returns protocol, product, version, OS hint, and confidence for every record. A failed match is a normal `unknown` result and never terminates the batch.

## Quick start

```bash
docker compose up --build
```

The server is available at `http://localhost:8080`. The client waits for the server health check, reads `testdata/input.json`, prints a table, and exits. To process another file, replace that file or run:

```bash
docker compose run --rm -v "$PWD/my-input.json:/data/input.json:ro" client
```

Without Docker:

```bash
go test ./...
go run ./cmd/server
go run ./cmd/client -input testdata/input.json -server http://localhost:8080
```

## API

`GET /health` returns `{"status":"ok","rules":31,"timestamp":"..."}`.

`POST /fingerprint` accepts either a JSON array or `{"records":[...]}`:

```json
[
  {"ip":"192.0.2.10","port":22,"banner":"SSH-2.0-OpenSSH_9.3 Debian-1"}
]
```

The response preserves input order:

```json
[
  {"ip":"192.0.2.10","port":22,"protocol":"SSH","product":"OpenSSH","version":"9.3","os_hint":"Debian","confidence":0.95}
]
```

Malformed JSON returns HTTP 400, unsupported methods return 405, and bodies over 32 MiB return 413. Individual unknown banners return `protocol: "unknown"` with confidence `0` unless a port-only hint is available (`0.3`).

## Rules

`rules/rules.json` is a data-only rule catalog. Each rule contains a Go RE2 expression, protocol/product metadata, optional named capture groups (`version`, `product`), OS extraction, supported ports, priority, and base confidence. Rules are compiled at startup and evaluated by priority, then confidence. Add or update signatures in this file and restart the server; no Go code change is required.

The catalog covers SSH (OpenSSH, Dropbear), HTTP (nginx, Apache, Jetty, IIS, Tomcat, lighttpd, generic Server headers), MySQL/MariaDB, Redis RESP, FTP, SMTP, POP3, IMAP, PostgreSQL, VNC, Telnet, and TLS handshakes.

## Deployment notes

Compose uses a private `backend` bridge network and the client reaches the server at `http://server:8080` through service DNS. The server health check executes the binary's own `/health` probe, and the client has a real `service_healthy` dependency. Both images are statically compiled in multi-stage builds and run from `scratch` as UID 65532 with a read-only root filesystem, dropped capabilities, and `no-new-privileges`.

## Layout

```
cmd/server       HTTP server entry point
cmd/client       standalone CLI client
internal/engine  rule loader and matcher
internal/server  HTTP handlers and middleware
rules            data-driven signatures
testdata         sample input
deploy           multi-stage Dockerfiles
```
