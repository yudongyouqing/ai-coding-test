# Banner Fingerprint Implementation Plan

1. Implement the rule model, loader, matcher, normalization, and table-driven tests.
2. Implement the HTTP server with bounded request bodies, JSON validation, health endpoint, and graceful unknown handling.
3. Implement the standalone client CLI with configurable server URL and input path.
4. Add multi-stage Dockerfiles, Compose health-gated startup, sample input, and operational README.
5. Run `gofmt`, `go test ./...`, build binaries, and validate Compose syntax.
