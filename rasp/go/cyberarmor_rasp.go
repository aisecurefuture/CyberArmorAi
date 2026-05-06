// Package cyberarmor provides RASP (Runtime Application Self-Protection) for Go HTTP services.
// Includes http.RoundTripper wrapper, gin/chi/echo middleware, and AI endpoint detection.
package cyberarmor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Config holds RASP configuration.
type Config struct {
	ControlPlaneURL string `json:"control_plane_url"`
	APIKey          string `json:"api_key"`
	BootstrapToken  string `json:"bootstrap_token"`
	TenantID        string `json:"tenant_id"`
	Mode            string `json:"mode"` // "monitor", "warn", "block", or "redact*"
	DLPEnabled      bool   `json:"dlp_enabled"`
	PromptInjection bool   `json:"prompt_injection"`
}

// DefaultConfig returns a config from environment variables.
func DefaultConfig() Config {
	mode := envOrAny("monitor", "CYBERARMOR_MODE")
	if mode == "" {
		mode = "monitor"
	}
	cfg := Config{
		ControlPlaneURL: envOrAny("http://localhost:8000", "CYBERARMOR_CONTROL_PLANE_URL", "CYBERARMOR_URL"),
		APIKey:          envOrAny("", "CYBERARMOR_API_KEY"),
		BootstrapToken:  envOrAny("", "CYBERARMOR_BOOTSTRAP_TOKEN"),
		TenantID:        envOrAny("default", "CYBERARMOR_TENANT_ID", "CYBERARMOR_TENANT"),
		Mode:            mode,
		DLPEnabled:      true,
		PromptInjection: true,
	}
	if cfg.BootstrapToken != "" && cfg.APIKey == "" {
		if redeemed, err := redeemBootstrapToken(cfg); err == nil {
			cfg = redeemed
		} else {
			log.Printf("[CyberArmor RASP] bootstrap redeem failed: %v", err)
		}
	}
	return cfg
}

func runtimeSubjectName() string {
	if name := os.Getenv("CYBERARMOR_RASP_SUBJECT_NAME"); name != "" {
		return name
	}
	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}
	return "go-rasp"
}

func redeemBootstrapToken(cfg Config) (Config, error) {
	payload := map[string]string{
		"bootstrap_token": cfg.BootstrapToken,
		"package_key":     "rasp-go",
		"subject_type":    "rasp_runtime",
		"subject_name":    runtimeSubjectName(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return cfg, err
	}

	req, err := http.NewRequest("POST", strings.TrimRight(cfg.ControlPlaneURL, "/")+"/bootstrap/redeem", bytes.NewReader(body))
	if err != nil {
		return cfg, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return cfg, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return cfg, fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}

	var redeem struct {
		APIKey   string `json:"api_key"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(respBody, &redeem); err != nil {
		return cfg, err
	}
	if redeem.APIKey != "" {
		cfg.APIKey = redeem.APIKey
	}
	if redeem.TenantID != "" {
		cfg.TenantID = redeem.TenantID
	}
	return cfg, nil
}

func envOrAny(defaultValue string, keys ...string) string {
	for _, key := range keys {
		v := os.Getenv(key)
		if v != "" {
			return v
		}
	}
	return defaultValue
}

// AI endpoint domains
var aiDomains = map[string]bool{
	"api.openai.com": true, "api.anthropic.com": true,
	"generativelanguage.googleapis.com": true, "api.cohere.ai": true,
	"api.mistral.ai": true, "api-inference.huggingface.co": true,
	"api.together.xyz": true, "api.replicate.com": true, "api.groq.com": true,
}

var azurePattern = regexp.MustCompile(`\.openai\.azure\.com$|\.cognitiveservices\.azure\.com$`)

func isAIEndpoint(host string) bool {
	h := strings.Split(host, ":")[0]
	return aiDomains[h] || azurePattern.MatchString(h)
}

// Prompt injection patterns
var promptInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+(a|an|in)`),
	regexp.MustCompile(`(?i)system\s*:\s*you\s+are`),
	regexp.MustCompile(`(?i)<\s*(system|prompt|instruction)\s*>`),
	regexp.MustCompile(`(?i)jailbreak|DAN\s+mode|bypass\s+filter`),
}

// DLP patterns
type dlpPattern struct {
	Name        string
	Category    string
	Placeholder string
	Pattern     *regexp.Regexp
}

var dlpPatterns = []dlpPattern{
	{"ssn", "pii", "[REDACTED-SSN]", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{"email", "pii", "[REDACTED-EMAIL]", regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
	{"phone", "pii", "[REDACTED-PHONE]", regexp.MustCompile(`\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b`)},
	{"credit_card", "pci", "[REDACTED-CARD]", regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`)},
	{"routing_number", "nacha", "[REDACTED-ROUTING]", regexp.MustCompile(`\b\d{9}\b`)},
	{"bank_account", "nacha", "[REDACTED-BANK-ACCOUNT]", regexp.MustCompile(`(?i)\b(?:account|acct)\s*(?:number|#|no\.?)?\s*[:=]?\s*\d{8,17}\b`)},
	{"npi", "npi", "[REDACTED-NPI]", regexp.MustCompile(`(?i)\b(?:npi\s*[:#]?\s*)?\d{10}\b`)},
	{"private_ip", "nonpublic", "[REDACTED-PRIVATE-IP]", regexp.MustCompile(`\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b`)},
	{"aws_key", "secrets", "[REDACTED-AWS-KEY]", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"openai_key", "secrets", "[REDACTED-OPENAI-KEY]", regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{20,}\b`)},
	{"github_token", "secrets", "[REDACTED-GITHUB-TOKEN]", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b`)},
	{"bearer_token", "secrets", "[REDACTED-BEARER]", regexp.MustCompile(`\bBearer\s+[A-Za-z0-9_.\-]{20,}\b`)},
	{"password", "secrets", "[REDACTED-PASSWORD]", regexp.MustCompile(`(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['"]?[^'"\s]{6,}`)},
	{"jwt", "secrets", "[REDACTED-JWT]", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\b`)},
	{"api_key", "secrets", "[REDACTED-API-KEY]", regexp.MustCompile(`(?i)\b(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['"]?[A-Za-z0-9_./+=-]{12,}`)},
	{"private_key", "secrets", "[REDACTED-PRIVATE-KEY]", regexp.MustCompile(`-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----[\s\S]*?-----END\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----`)},
}

var redactionCategories = map[string]map[string]bool{
	"redact":           {"secrets": true, "pii": true, "pci": true, "nacha": true, "npi": true, "nonpublic": true},
	"redact-secrets":   {"secrets": true},
	"redact-pii":       {"pii": true},
	"redact-pci":       {"pci": true},
	"redact-nacha":     {"nacha": true},
	"redact-npi":       {"npi": true},
	"redact-nonpublic": {"nonpublic": true},
}

func normalizeMode(mode string) string {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(mode), "_", "-"))
	if normalized == "redact-nachi" {
		return "redact-nacha"
	}
	return normalized
}

func isRedactionMode(mode string) bool {
	_, ok := redactionCategories[normalizeMode(mode)]
	return ok
}

func scanDLP(body string) []string {
	var findings []string
	for _, d := range dlpPatterns {
		if d.Pattern.MatchString(body) {
			findings = append(findings, d.Name)
		}
	}
	return findings
}

func redactText(body, mode string) (string, []string) {
	categories, ok := redactionCategories[normalizeMode(mode)]
	if !ok {
		categories = redactionCategories["redact"]
	}
	redacted := body
	var findings []string
	for _, d := range dlpPatterns {
		if !categories[d.Category] {
			continue
		}
		if d.Pattern.MatchString(redacted) {
			redacted = d.Pattern.ReplaceAllString(redacted, d.Placeholder)
			findings = append(findings, d.Name)
		}
	}
	return redacted, findings
}

func redactJSONValue(value interface{}, mode string) interface{} {
	switch typed := value.(type) {
	case string:
		redacted, _ := redactText(typed, mode)
		return redacted
	case []interface{}:
		for i, item := range typed {
			typed[i] = redactJSONValue(item, mode)
		}
		return typed
	case map[string]interface{}:
		for key, item := range typed {
			typed[key] = redactJSONValue(item, mode)
		}
		return typed
	default:
		return value
	}
}

func redactProviderPayload(body, mode string) string {
	var payload interface{}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		redacted, _ := redactText(body, mode)
		return redacted
	}
	redacted := redactJSONValue(payload, mode)
	out, err := json.Marshal(redacted)
	if err != nil {
		redactedText, _ := redactText(body, mode)
		return redactedText
	}
	return string(out)
}

// InspectionResult holds the result of request inspection.
type InspectionResult struct {
	Allowed      bool   `json:"allowed"`
	Reason       string `json:"reason,omitempty"`
	RedactedBody string `json:"redacted_body,omitempty"`
}

// Inspector is the main RASP inspector.
type Inspector struct {
	cfg    Config
	mu     sync.Mutex
	events []map[string]interface{}
}

// New creates a new Inspector with the given config.
func New(cfg Config) *Inspector {
	return &Inspector{cfg: cfg}
}

func (ins *Inspector) record(evtType, url, detail string) {
	ins.mu.Lock()
	ins.events = append(ins.events, map[string]interface{}{
		"ts": time.Now().Unix(), "type": evtType, "url": url,
		"detail": truncate(detail, 200), "tenant": ins.cfg.TenantID,
	})
	if len(ins.events) >= 50 {
		batch := ins.events
		ins.events = nil
		go ins.flush(batch)
	}
	ins.mu.Unlock()
}

func (ins *Inspector) flush(batch []map[string]interface{}) {
	if ins.cfg.ControlPlaneURL == "" {
		return
	}
	body, _ := json.Marshal(batch)
	req, _ := http.NewRequest("POST", ins.cfg.ControlPlaneURL+"/telemetry/ingest", bytes.NewReader(body))
	if req != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", ins.cfg.APIKey)
		client := &http.Client{Timeout: 5 * time.Second}
		client.Do(req) //nolint:errcheck
	}
}

// Inspect checks a request body for AI security threats.
func (ins *Inspector) Inspect(url, body string) InspectionResult {
	host := extractHost(url)
	if !isAIEndpoint(host) {
		return InspectionResult{Allowed: true}
	}
	ins.record("ai_request", url, "")

	if ins.cfg.PromptInjection && body != "" {
		for _, p := range promptInjectionPatterns {
			if p.MatchString(body) {
				ins.record("prompt_injection", url, p.String())
				if ins.cfg.Mode == "block" {
					return InspectionResult{Allowed: false, Reason: fmt.Sprintf("Prompt injection: %s", p.String())}
				}
			}
		}
	}

	if ins.cfg.DLPEnabled && body != "" {
		findings := scanDLP(body)
		if len(findings) > 0 {
			ins.record("sensitive_data", url, strings.Join(findings, ","))
			if ins.cfg.Mode == "block" {
				return InspectionResult{Allowed: false, Reason: "Sensitive data: " + strings.Join(findings, ",")}
			}
			if isRedactionMode(ins.cfg.Mode) {
				redactedBody := redactProviderPayload(body, ins.cfg.Mode)
				if redactedBody != body {
					ins.record("sensitive_data_redacted", url, strings.Join(findings, ","))
					return InspectionResult{Allowed: true, Reason: "Sensitive data redacted", RedactedBody: redactedBody}
				}
			}
		}
	}

	return InspectionResult{Allowed: true}
}

// InspectResponse checks an AI response and redacts sensitive data in redact modes.
func (ins *Inspector) InspectResponse(url, body string) InspectionResult {
	host := extractHost(url)
	if body == "" || !isAIEndpoint(host) || !isRedactionMode(ins.cfg.Mode) {
		return InspectionResult{Allowed: true}
	}
	findings := scanDLP(body)
	if len(findings) == 0 {
		return InspectionResult{Allowed: true}
	}
	redactedBody := redactProviderPayload(body, ins.cfg.Mode)
	if redactedBody != body {
		ins.record("sensitive_response_redacted", url, strings.Join(findings, ","))
		return InspectionResult{Allowed: true, Reason: "Sensitive response data redacted", RedactedBody: redactedBody}
	}
	return InspectionResult{Allowed: true}
}

// RoundTripper wraps an http.RoundTripper with AI inspection.
func (ins *Inspector) RoundTripper(inner http.RoundTripper) http.RoundTripper {
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &raspTransport{inner: inner, ins: ins}
}

type raspTransport struct {
	inner http.RoundTripper
	ins   *Inspector
}

func (rt *raspTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == "POST" && req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
			result := rt.ins.Inspect(req.URL.String(), string(body))
			if !result.Allowed {
				return &http.Response{
					StatusCode: 403,
					Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"error":"%s"}`, result.Reason))),
				}, nil
			}
			if result.RedactedBody != "" {
				redacted := []byte(result.RedactedBody)
				req.Body = io.NopCloser(bytes.NewReader(redacted))
				req.ContentLength = int64(len(redacted))
				req.Header.Set("Content-Length", fmt.Sprintf("%d", len(redacted)))
			}
		}
	}
	resp, err := rt.inner.RoundTrip(req)
	if err != nil || resp == nil || !isRedactionMode(rt.ins.cfg.Mode) || resp.Body == nil {
		return resp, err
	}
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, err
	}
	responseResult := rt.ins.InspectResponse(req.URL.String(), string(body))
	if responseResult.RedactedBody != "" {
		redacted := []byte(responseResult.RedactedBody)
		resp.Body = io.NopCloser(bytes.NewReader(redacted))
		resp.ContentLength = int64(len(redacted))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(redacted)))
	} else {
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	return resp, err
}

// HTTPMiddleware returns an http.Handler middleware.
func (ins *Inspector) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			host := r.Header.Get("X-Forwarded-Host")
			if host == "" {
				host = r.Host
			}
			if isAIEndpoint(host) {
				body, err := io.ReadAll(r.Body)
				if err == nil {
					r.Body = io.NopCloser(bytes.NewReader(body))
					result := ins.Inspect(fmt.Sprintf("https://%s%s", host, r.URL.Path), string(body))
					if !result.Allowed {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(403)
						json.NewEncoder(w).Encode(map[string]string{"error": result.Reason})
						return
					}
					if result.RedactedBody != "" {
						redacted := []byte(result.RedactedBody)
						r.Body = io.NopCloser(bytes.NewReader(redacted))
						r.ContentLength = int64(len(redacted))
						r.Header.Set("Content-Length", fmt.Sprintf("%d", len(redacted)))
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func extractHost(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rawURL = rawURL[i+3:]
	}
	if i := strings.Index(rawURL, "/"); i >= 0 {
		rawURL = rawURL[:i]
	}
	return strings.Split(rawURL, ":")[0]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func init() {
	log.Println("[CyberArmor RASP] Go module loaded")
}
