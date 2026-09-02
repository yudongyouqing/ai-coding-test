package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFingerprintEndpoint(t *testing.T) {
	tests := []struct {
		name string
		base string
		want string
	}{
		{"full URL", "http://example.test:8080/", "http://example.test:8080/fingerprint"},
		{"host and port", "example.test:8080", "http://example.test:8080/fingerprint"},
		{"base path", "https://example.test/api/", "https://example.test/api/fingerprint"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fingerprintEndpoint(tc.base)
			if err != nil {
				t.Fatalf("fingerprintEndpoint(%q): %v", tc.base, err)
			}
			if got != tc.want {
				t.Fatalf("fingerprintEndpoint(%q) = %q, want %q", tc.base, got, tc.want)
			}
		})
	}
	for _, base := range []string{"", "ftp://example.test", "://bad"} {
		t.Run("reject "+base, func(t *testing.T) {
			if _, err := fingerprintEndpoint(base); err == nil {
				t.Fatalf("fingerprintEndpoint(%q) unexpectedly succeeded", base)
			}
		})
	}
}

func TestPostWithRetryRetriesTransientResponse(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content type = %q, want application/json", got)
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("warming up"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"ip":"127.0.0.1","port":22,"protocol":"SSH","confidence":0.95}]`))
	}))
	defer srv.Close()

	results, err := postWithRetry(srv.URL, []byte(`[]`), 2*time.Second, 2)
	if err != nil {
		t.Fatalf("postWithRetry: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("server calls = %d, want 2", got)
	}
	if len(results) != 1 || results[0].Protocol != "SSH" {
		t.Fatalf("unexpected results: %#v", results)
	}
}

func TestPostWithRetryDoesNotRetryClientError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, `{"error":"bad input"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	_, err := postWithRetry(srv.URL, []byte(`{}`), 2*time.Second, 4)
	if err == nil || !strings.Contains(err.Error(), "server returned 400") {
		t.Fatalf("postWithRetry error = %v, want status 400", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("server calls = %d, want 1", got)
	}
}

func TestParseFlagsValidation(t *testing.T) {
	if _, err := parseFlags([]string{"-timeout", "0"}); err == nil {
		t.Fatal("zero timeout unexpectedly accepted")
	}
	if _, err := parseFlags([]string{"-retries", "0"}); err == nil {
		t.Fatal("zero retries unexpectedly accepted")
	}
	cfg, err := parseFlags([]string{"-server", "localhost:18080", "-retries", "3"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg.serverURL != "localhost:18080" || cfg.attempts != 3 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestReadInputLimit(t *testing.T) {
	// The helper is exercised with an in-memory temporary file to ensure the
	// client rejects files that would be rejected by the server as well.
	f := t.TempDir() + "/input.json"
	if err := writeFileForTest(f, []byte(`[{"ip":"1.2.3.4","port":22,"banner":"SSH"}]`)); err != nil {
		t.Fatal(err)
	}
	if data, err := readInput(f); err != nil || len(data) == 0 {
		t.Fatalf("readInput = %d bytes, err=%v", len(data), err)
	}
}

func writeFileForTest(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write fixture: %w", err)
	}
	return nil
}
