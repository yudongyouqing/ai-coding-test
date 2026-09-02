// Package server 提供 HTTP API：POST /fingerprint（批量识别）、GET /health（健康检查）。
package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"banner-fingerprint/internal/engine"
)

const maxBodyBytes = 32 << 20 // 32MB，超出直接 413

type API struct {
	engine *engine.Engine
}

func New(e *engine.Engine) *API { return &API{engine: e} }

// Routes 组装带日志与 panic 恢复中间件的路由。
func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/fingerprint", a.handleFingerprint)
	return recoverMW(loggingMW(mux))
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"rules":      a.engine.RulesCount(),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	})
}

func (a *API) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "body too large or unreadable: "+err.Error())
		return
	}
	records, err := engine.DecodeRecords(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	results := a.engine.IdentifyAll(records) // 无法识别的条目在结果里返回 unknown，不会失败
	w.Header().Set("X-Processed-Count", strconv.Itoa(len(results)))
	writeJSON(w, http.StatusOK, results)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func loggingMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, sw.status, time.Since(start).Round(time.Microsecond))
	})
}

// recoverMW 兜住 handler panic，转成 500，保证服务不崩。
func recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered: %v", rec)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
