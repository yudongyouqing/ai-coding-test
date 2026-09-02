// fpserver：指纹识别 HTTP 服务。
// 用法：fpserver [-addr :8080] [-rules rules/rules.json]
//       fpserver -selfcheck   # 对自身 /health 探活后退出，供 Docker healthcheck 使用（scratch 镜像无 shell/wget）
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"banner-fingerprint/internal/engine"
	"banner-fingerprint/internal/server"
)

func main() {
	addr := flag.String("addr", envOr("ADDR", ":8080"), "listen address")
	rulesPath := flag.String("rules", envOr("RULES_PATH", "rules/rules.json"), "path to rules file")
	selfcheck := flag.Bool("selfcheck", false, "probe GET /health on -addr and exit 0/1")
	flag.Parse()

	if *selfcheck {
		os.Exit(selfcheckRun(*addr))
	}

	eng, err := engine.Load(*rulesPath)
	if err != nil {
		log.Fatalf("load rules: %v", err)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.New(eng).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("fingerprint server listening on %s (rules=%s, %d rules)", *addr, *rulesPath, eng.RulesCount())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	// 优雅退出：收到 SIGINT/SIGTERM 后给在途请求 10 秒收尾。
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("shutting down ...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	log.Println("stopped")
}

func selfcheckRun(addr string) int {
	target := "http://" + addr
	if strings.HasPrefix(addr, ":") {
		target = "http://127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target + "/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, "selfcheck failed:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "selfcheck: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
