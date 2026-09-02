// Package engine 是纯数据驱动的 banner 指纹识别引擎：
// 规则从 rules.json 加载（与代码解耦），识别过程只做正则匹配与打分，
// 任何无法识别的输入都降级为 protocol="unknown"，绝不报错。
package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// InputRecord 是 client 提交的一条原始扫描记录。
type InputRecord struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result 是单条记录的识别结果，字段顺序即输出 JSON 顺序。
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// Rule 是 rules.json 中一条规则的声明格式。
type Rule struct {
	ID                 string  `json:"id"`
	Match              string  `json:"match"` // RE2 正则，命中才候选
	Protocol           string  `json:"protocol"`
	Product            string  `json:"product"`       // 固定产品名（优先）
	ProductGroup       string  `json:"product_group"` // 或从命名捕获组提取产品（如未知 Server 头）
	VersionGroup       string  `json:"version_group"` // 版本捕获组名，默认 "version"
	VersionStripPrefix string  `json:"version_strip_prefix"`
	OS                 string  `json:"os"`       // 固定 OS 提示
	OSRegex            string  `json:"os_regex"` // 从 banner 提取 OS 关键词
	Ports              []int   `json:"ports"`
	Priority           int     `json:"priority"` // 多规则命中时高者优先
	Confidence         float64 `json:"confidence"`
}

type compiledRule struct {
	Rule
	re   *regexp.Regexp
	osRe *regexp.Regexp
}

type rulesFile struct {
	Rules     []Rule            `json:"rules"`
	PortHints map[string]string `json:"port_hints"`
}

// Engine 持有编译后的规则，线程安全（加载后只读）。
type Engine struct {
	rules     []compiledRule
	portHints map[string]string
}

const (
	maxBannerBytes = 8192 // 防御性截断，限制正则处理成本
	portBonus      = 0.02 // banner 命中且端口也吻合时的加分
	maxConfidence  = 0.99
	fallbackConf   = 0.3 // 仅端口猜测的兜底置信度
)

// Load 读取并编译规则文件。规则文件损坏直接启动失败（fail fast），
// 避免带着残缺规则静默给出错误结果。
func Load(path string) (*Engine, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules %s: %w", path, err)
	}
	var rf rulesFile
	if err := json.Unmarshal(raw, &rf); err != nil {
		return nil, fmt.Errorf("parse rules %s: %w", path, err)
	}
	if len(rf.Rules) == 0 {
		return nil, fmt.Errorf("rules file %s contains no rules", path)
	}
	e := &Engine{portHints: rf.PortHints}
	for _, r := range rf.Rules {
		re, err := regexp.Compile(r.Match)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		c := compiledRule{Rule: r, re: re}
		if r.OSRegex != "" {
			osRe, err := regexp.Compile(r.OSRegex)
			if err != nil {
				return nil, fmt.Errorf("rule %s os_regex: %w", r.ID, err)
			}
			c.osRe = osRe
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

// RulesCount 返回已加载规则数（健康检查展示用）。
func (e *Engine) RulesCount() int { return len(e.rules) }

// IdentifyAll 批量识别，逐条独立处理，单条异常不影响其余。
func (e *Engine) IdentifyAll(records []InputRecord) []Result {
	out := make([]Result, 0, len(records))
	for _, r := range records {
		out = append(out, e.Identify(r))
	}
	return out
}

// Identify 识别一条记录：所有规则求最优（priority > confidence > 端口加分），
// 无规则命中时按端口兜底猜测，否则返回 unknown。
func (e *Engine) Identify(rec InputRecord) Result {
	res := Result{IP: rec.IP, Port: rec.Port, Protocol: "unknown"}
	banner := rec.Banner
	if len(banner) > maxBannerBytes {
		banner = banner[:maxBannerBytes]
	}
	if banner == "" {
		applyPortHint(&res, e.portHints, rec.Port)
		return res
	}

	var best *compiledRule
	var bestMatch []string
	bestConf := 0.0
	for i := range e.rules {
		r := &e.rules[i]
		m := r.re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		conf := r.Confidence
		if intIn(r.Ports, rec.Port) {
			conf = math.Min(maxConfidence, conf+portBonus)
		}
		// Rules are data loaded at runtime; keep externally visible confidence
		// within the API contract even when a custom rule has a bad value.
		conf = clampConfidence(conf)
		if best == nil || r.Priority > best.Priority ||
			(r.Priority == best.Priority && conf > bestConf) {
			best, bestMatch, bestConf = r, m, conf
		}
	}
	if best == nil {
		applyPortHint(&res, e.portHints, rec.Port)
		return res
	}

	res.Protocol = best.Protocol
	res.Confidence = round2(bestConf)

	if v := extractGroup(best.re, bestMatch, orDefault(best.VersionGroup, "version")); v != "" {
		res.Version = strings.TrimPrefix(v, best.VersionStripPrefix)
	}
	res.Product = best.Product
	if best.ProductGroup != "" {
		if p := strings.TrimSpace(extractGroup(best.re, bestMatch, best.ProductGroup)); p != "" {
			res.Product = p
		}
	}
	switch {
	case best.OS != "":
		res.OSHint = best.OS
	case best.osRe != nil:
		if om := best.osRe.FindStringSubmatch(banner); om != nil {
			if len(om) > 1 {
				res.OSHint = om[1]
			} else {
				res.OSHint = om[0]
			}
		}
	}
	return res
}

// DecodeRecords 同时兼容两种请求体：顶层数组 或 {"records":[...]} 包装。
func DecodeRecords(body []byte) ([]InputRecord, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, nil
	}
	var recs []InputRecord
	switch trimmed[0] {
	case '[':
		if err := json.Unmarshal([]byte(trimmed), &recs); err != nil {
			return nil, fmt.Errorf("body must be a JSON array of {ip,port,banner}: %v", err)
		}
	case '{':
		var wrapper struct {
			Records []InputRecord `json:"records"`
		}
		if err := json.Unmarshal([]byte(trimmed), &wrapper); err != nil {
			return nil, fmt.Errorf("body must be {\"records\":[...]}: %v", err)
		}
		recs = wrapper.Records
	default:
		return nil, fmt.Errorf(`body must be a JSON array or {"records":[...]}`)
	}
	return recs, nil
}

func applyPortHint(res *Result, hints map[string]string, port int) {
	if p, ok := hints[strconv.Itoa(port)]; ok {
		res.Protocol, res.Confidence = p, fallbackConf
	}
}

func orDefault(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

func extractGroup(re *regexp.Regexp, m []string, name string) string {
	i := re.SubexpIndex(name)
	if i < 0 || i >= len(m) {
		return ""
	}
	return m[i]
}

func intIn(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func clampConfidence(f float64) float64 {
	if math.IsNaN(f) || f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}
