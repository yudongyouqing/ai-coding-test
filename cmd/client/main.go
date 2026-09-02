// Command fpclient reads scan banners from a JSON file and sends them to the
// fingerprint server. It is intentionally a one-shot process so it can be
// used as a Docker Compose job or run directly from a shell.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"banner-fingerprint/internal/engine"
)

const (
	maxInputBytes    = 32 << 20 // Keep in sync with the server request limit.
	maxResponseBytes = 64 << 20
)

type config struct {
	input     string
	serverURL string
	output    string
	timeout   time.Duration
	attempts  int
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "client error:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		return err
	}

	raw, err := readInput(cfg.input)
	if err != nil {
		return err
	}
	records, err := engine.DecodeRecords(raw)
	if err != nil {
		return fmt.Errorf("parse input %s: %w", cfg.input, err)
	}

	endpoint, err := fingerprintEndpoint(cfg.serverURL)
	if err != nil {
		return err
	}
	fmt.Printf("loaded %d records from %s, server=%s\n", len(records), cfg.input, endpoint)

	results, err := postWithRetry(endpoint, raw, cfg.timeout, cfg.attempts)
	if err != nil {
		return err
	}

	printTable(results)
	printSummary(results)

	if cfg.output != "" {
		enc, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("encode output: %w", err)
		}
		if err := os.WriteFile(cfg.output, append(enc, '\n'), 0o644); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		fmt.Printf("results written to %s\n", cfg.output)
	}
	return nil
}

func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("fpclient", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfg := config{}
	fs.StringVar(&cfg.input, "input", "testdata/input.json", "input JSON file (array or {records:[...]})")
	fs.StringVar(&cfg.serverURL, "server", envOr("SERVER_ADDR", "http://localhost:8080"), "fingerprint server URL")
	fs.StringVar(&cfg.output, "output", "", "optional path to write results JSON")
	fs.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "timeout for each HTTP request")
	fs.IntVar(&cfg.attempts, "retries", 5, "maximum HTTP attempts (including the first request)")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if cfg.timeout <= 0 {
		return config{}, errors.New("timeout must be greater than zero")
	}
	if cfg.attempts < 1 {
		return config{}, errors.New("retries must be at least 1")
	}
	return cfg, nil
}

func readInput(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if len(data) > maxInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxInputBytes)
	}
	return data, nil
}

// fingerprintEndpoint accepts both http://host:port and host:port forms while
// rejecting malformed or unsupported URLs before the retry loop starts.
func fingerprintEndpoint(base string) (string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		return "", errors.New("server URL must not be empty")
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid server URL %q", base)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("server URL scheme must be http or https (got %q)", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/fingerprint"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// postWithRetry sends one request per attempt. Network failures and 5xx/429
// responses are retried; malformed requests (4xx) and malformed successful
// responses fail immediately because retrying cannot change their outcome.
func postWithRetry(endpoint string, body []byte, timeout time.Duration, attempts int) ([]engine.Result, error) {
	if timeout <= 0 {
		return nil, errors.New("timeout must be greater than zero")
	}
	if attempts < 1 {
		attempts = 1
	}
	client := &http.Client{Timeout: timeout}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
			resp.Body.Close()
			if readErr != nil {
				return nil, fmt.Errorf("read response: %w", readErr)
			}
			if len(data) > maxResponseBytes {
				return nil, fmt.Errorf("server response exceeds %d bytes", maxResponseBytes)
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				var results []engine.Result
				if err := json.Unmarshal(data, &results); err != nil {
					return nil, fmt.Errorf("decode response: %w", err)
				}
				return results, nil
			}
			lastErr = fmt.Errorf("server returned %d: %s", resp.StatusCode, truncate(string(data), 200))
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return nil, lastErr
			}
		}

		if attempt < attempts {
			wait := retryDelay(attempt)
			fmt.Fprintf(os.Stderr, "attempt %d/%d failed (%v), retrying in %s\n", attempt, attempts, lastErr, wait)
			time.Sleep(wait)
		}
	}
	return nil, fmt.Errorf("server unavailable after %d attempts: %w", attempts, lastErr)
}

func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		return 0
	}
	d := 250 * time.Millisecond * time.Duration(1<<(attempt-1))
	if d > 5*time.Second {
		return 5 * time.Second
	}
	return d
}

func printTable(results []engine.Result) {
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS\tCONFIDENCE")
	fmt.Fprintln(w, "--\t----\t--------\t-------\t-------\t--\t----------")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP, r.Port, r.Protocol, orDash(r.Product), orDash(r.Version), orDash(r.OSHint), r.Confidence)
	}
	_ = w.Flush()
}

func printSummary(results []engine.Result) {
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Protocol]++
	}
	protos := make([]string, 0, len(counts))
	for p := range counts {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	fmt.Printf("\nsummary: %d records", len(results))
	for _, p := range protos {
		fmt.Printf(" | %s: %d", p, counts[p])
	}
	fmt.Println()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	if n < 0 {
		n = 0
	}
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
