package engine

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := Load(filepath.Join("..", "..", "rules", "rules.json"))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return e
}

// 覆盖题目示例数据 + 扩展场景（MariaDB/TLS/unknown/端口兜底等）。
func TestIdentify(t *testing.T) {
	e := loadTestEngine(t)
	cases := []struct {
		name      string
		rec       InputRecord
		wantProto string
		wantProd  string
		wantVer   string
		wantOS    string
		wantConf  float64
	}{
		{"openssh-ubuntu", InputRecord{"1.2.3.4", 22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}, "SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95},
		{"nginx", InputRecord{"1.2.3.5", 80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"}, "HTTP", "nginx", "1.24.0", "", 0.9},
		{"apache", InputRecord{"1.2.3.6", 443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"}, "HTTP", "Apache", "2.4.57", "", 0.9},
		{"mysql8", InputRecord{"1.2.3.7", 3306, "J\x00\x00\x00\n8.0.32\x00"}, "MySQL", "MySQL", "8.0.32", "", 0.9},
		{"redis-err", InputRecord{"1.2.3.8", 6379, "-ERR wrong number of arguments for 'get' command"}, "Redis", "Redis", "", "", 0.7},
		{"proftpd", InputRecord{"1.2.3.9", 21, "220 ProFTPD 1.3.7 Server (ProFTPD)"}, "FTP", "ProFTPD", "1.3.7", "", 0.9},
		{"jetty", InputRecord{"1.2.3.10", 8080, "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"}, "HTTP", "Jetty", "9.4.51", "", 0.85},
		{"openssh-debian", InputRecord{"1.2.3.11", 22, "SSH-2.0-OpenSSH_9.3 Debian-1"}, "SSH", "OpenSSH", "9.3", "Debian", 0.95},
		{"nginx-ubuntu", InputRecord{"1.2.3.12", 80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"}, "HTTP", "nginx", "1.18.0", "Ubuntu", 0.9},
		{"apache-ubuntu", InputRecord{"1.2.3.13", 443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"}, "HTTP", "Apache", "2.4.41", "Ubuntu", 0.9},
		{"mysql57", InputRecord{"1.2.3.14", 3306, "J\x00\x00\x00\n5.7.42\x00"}, "MySQL", "MySQL", "5.7.42", "", 0.9},
		{"redis-pong", InputRecord{"1.2.3.15", 6379, "+PONG"}, "Redis", "Redis", "", "", 0.9},
		{"vsftpd", InputRecord{"1.2.3.16", 21, "220 (vsFTPd 3.0.5)"}, "FTP", "vsftpd", "3.0.5", "", 0.9},
		{"nginx-8443", InputRecord{"1.2.3.17", 8443, "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3"}, "HTTP", "nginx", "1.25.3", "", 0.9},
		{"openssh-legacy", InputRecord{"1.2.3.18", 22, "SSH-1.99-OpenSSH_4.3"}, "SSH", "OpenSSH", "4.3", "", 0.95},
		{"tls-handshake", InputRecord{"1.2.3.19", 9999, "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"}, "SSL/TLS", "", "", "", 0.6},
		{"iis", InputRecord{"1.2.3.20", 8888, "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"}, "HTTP", "Microsoft IIS", "10.0", "Windows", 0.88},
		{"redis-noauth", InputRecord{"1.2.3.21", 6379, "-NOAUTH Authentication required."}, "Redis", "Redis", "", "", 0.9},
		{"pureftpd", InputRecord{"1.2.3.22", 21, "220 Welcome to Pure-FTPd"}, "FTP", "Pure-FTPd", "", "", 0.9},
		{"unknown-quit", InputRecord{"1.2.3.23", 12345, "QUIT\r\n"}, "unknown", "", "", "", 0},
		{"mariadb", InputRecord{"9.9.9.9", 3306, "\x56\x00\x00\x00\n5.5.5-10.11.6-MariaDB\x00"}, "MySQL", "MariaDB", "10.11.6-MariaDB", "", 0.95},
		{"dropbear", InputRecord{"9.9.9.8", 22, "SSH-2.0-dropbear_2020.81"}, "SSH", "Dropbear", "2020.81", "", 0.95},
		{"generic-server-header", InputRecord{"9.9.9.7", 80, "HTTP/1.1 200 OK\r\nServer: Caddy\r\n"}, "HTTP", "Caddy", "", "", 0.62},
		{"empty-banner-port-hint", InputRecord{"9.9.9.6", 6379, ""}, "Redis", "", "", "", 0.3},
		{"garbage-port-hint", InputRecord{"9.9.9.5", 3306, "zzz-nothing"}, "MySQL", "", "", "", 0.3},
		{"postfix", InputRecord{"9.9.9.4", 25, "220 mail.example.com ESMTP Postfix"}, "SMTP", "Postfix", "", "", 0.9},
	}
	for _, c := range cases {
		got := e.Identify(c.rec)
		if got.Protocol != c.wantProto || got.Product != c.wantProd || got.Version != c.wantVer || got.OSHint != c.wantOS {
			t.Errorf("%s: got {proto=%q prod=%q ver=%q os=%q conf=%.2f}, want {proto=%q prod=%q ver=%q os=%q}",
				c.name, got.Protocol, got.Product, got.Version, got.OSHint, got.Confidence,
				c.wantProto, c.wantProd, c.wantVer, c.wantOS)
		}
		if math.Abs(got.Confidence-c.wantConf) > 0.011 {
			t.Errorf("%s: confidence got %.2f want %.2f", c.name, got.Confidence, c.wantConf)
		}
		if got.IP != c.rec.IP || got.Port != c.rec.Port {
			t.Errorf("%s: ip/port not echoed back", c.name)
		}
	}
}

// 识别失败必须降级为 unknown，绝不能 panic（题目硬性要求）。
func TestIdentifyNeverPanics(t *testing.T) {
	e := loadTestEngine(t)
	nasty := []string{"", "\x00\x00\x00", "(((((((((((((((((((((", longBanner, "\n\r\n", "-ERR", "SSH-", "HTTP/1.1"}
	for i, b := range nasty {
		r := e.Identify(InputRecord{IP: "10.0.0.1", Port: 65000 - i, Banner: b})
		if r.Protocol == "" {
			t.Errorf("case %d: protocol must never be empty", i)
		}
	}
}

func TestDecodeRecords(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{name: "array", body: `[{"ip":"127.0.0.1","port":80,"banner":"HTTP/1.1 200 OK"}]`, want: 1},
		{name: "wrapper", body: `{"records":[{"ip":"127.0.0.1","port":22,"banner":"SSH-2.0-test"}]}`, want: 1},
		{name: "empty", body: " \n\t", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeRecords([]byte(tc.body))
			if err != nil || len(got) != tc.want {
				t.Fatalf("DecodeRecords() = %#v, %v; want %d records", got, err, tc.want)
			}
		})
	}
	if _, err := DecodeRecords([]byte(`{"records":`)); err == nil {
		t.Fatal("malformed JSON should return an error")
	}
}

func TestConfidenceIsClamped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	rules := `{"rules":[{"id":"high","match":"^x$","protocol":"X","confidence":9},{"id":"low","match":"^y$","protocol":"Y","confidence":-2}]}`
	if err := os.WriteFile(path, []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Identify(InputRecord{Banner: "x"}).Confidence; got != 1 {
		t.Fatalf("high confidence = %v, want 1", got)
	}
	if got := e.Identify(InputRecord{Banner: "y"}).Confidence; got != 0 {
		t.Fatalf("low confidence = %v, want 0", got)
	}
}

func TestLoadRejectsInvalidRules(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"invalid-json": "{",
		"empty-rules":  `{"rules":[]}`,
		"bad-regex":    `{"rules":[{"id":"bad","match":"[","protocol":"X"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, "-", "_")+".json")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load() unexpectedly succeeded")
			}
		})
	}
}

func TestResultJSONShape(t *testing.T) {
	b, err := json.Marshal(Result{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Confidence: .95})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"os_hint":""`) {
		t.Fatalf("result JSON missing os_hint: %s", b)
	}
}

var longBanner = func() string {
	b := make([]byte, 1<<20)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return string(b)
}()
