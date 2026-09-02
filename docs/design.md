# Banner Fingerprint System Design

## Goal

Provide a Go server that accepts a batch of `{ip, port, banner}` records and returns stable fingerprint records, plus a standalone Go client that reads a JSON file and calls the server.

## Architecture

The server loads ordered matching rules from `rules/rules.json`. Each rule contains an RE2 expression, protocol/product metadata, optional version and OS named capture groups, port hints, priority, and confidence. Runtime code only evaluates rules and normalizes results; adding a signature is therefore a data-only change.

The HTTP API exposes `GET /health` and `POST /fingerprint`. Invalid individual records are normalized to an `unknown` result instead of aborting the batch. Unknown banners also fall back to a protocol inferred from the port at low confidence, or `unknown` when no hint exists.

Docker Compose runs isolated `server` and `client` services on a private network. The client depends on the server health check and uses the service DNS name, not a host address. Images use multi-stage builds, a distroless runtime, non-root execution, read-only root filesystems, dropped capabilities, and a temporary writable directory.

## Verification

Unit tests cover representative SSH, HTTP, MySQL, Redis, FTP, unknown, malformed input, and rule loading paths. A smoke test invokes the HTTP handler directly; Compose configuration is validated with `docker compose config` when Docker is available.
