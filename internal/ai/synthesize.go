package ai

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Provider names for the pluggable backends.
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai"
)

// Default endpoints and models per provider. BaseURL/Model in Config override
// these, so any OpenAI-compatible server (a local model, OpenRouter, Azure, a
// gateway) is reachable by pointing BaseURL and Model at it with provider "openai".
const (
	defaultAnthropicBaseURL = "https://api.anthropic.com"
	defaultOpenAIBaseURL    = "https://api.openai.com"
	defaultAnthropicModel   = "claude-haiku-4-5"
	defaultOpenAIModel      = "gpt-4o-mini"
	anthropicVersion        = "2023-06-01"
	defaultTimeout          = 30 * time.Second
	maxResponseBytes        = 1 << 20 // 1 MiB cap on the model response body
)

// Config configures policy synthesis. It is provider-agnostic: Provider selects
// the request/response adapter, and BaseURL/Model let a caller target any
// compatible endpoint. Enabled gates the whole feature; when false, callers should
// not construct a synthesizer at all.
type Config struct {
	Enabled     bool
	Provider    string        // "anthropic" (default) or "openai"
	Model       string        // provider default when empty
	BaseURL     string        // provider default when empty
	APIKey      string        // required; feature is skipped when empty
	Timeout     time.Duration // defaultTimeout when zero
	InsecureTLS bool          // mirror the crawler's -insecure behaviour
}

// EffectiveModel is the exported view of the model id that will actually be used
// for the configured provider (Model, or the provider default when unset). Callers
// need it to key the policy cache by the same model the request will target.
func (c Config) EffectiveModel() string { return c.model() }

// Model returns the effective model id for the configured provider, filling in the
// per-provider default when Model is unset.
func (c Config) model() string {
	if c.Model != "" {
		return c.Model
	}
	if c.provider() == ProviderOpenAI {
		return defaultOpenAIModel
	}
	return defaultAnthropicModel
}

func (c Config) provider() string {
	if c.Provider == ProviderOpenAI {
		return ProviderOpenAI
	}
	return ProviderAnthropic
}

func (c Config) baseURL() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	if c.provider() == ProviderOpenAI {
		return defaultOpenAIBaseURL
	}
	return defaultAnthropicBaseURL
}

// Synthesizer turns a SiteDigest into a scoring Policy. It is an interface so the
// crawl can be exercised offline with a canned implementation, while production
// uses the HTTP-backed synthesizer.
type Synthesizer interface {
	Synthesize(ctx context.Context, digest SiteDigest) (*Policy, error)
}

// httpSynthesizer calls a chat/completions-style API and parses a Policy out of the
// model's reply.
type httpSynthesizer struct {
	cfg    Config
	client *http.Client
}

// NewHTTPSynthesizer builds a Synthesizer that talks to the configured provider
// over plain net/http (no third-party SDK). It honours HTTPS_PROXY via the default
// transport and mirrors the crawler's TLS-verification setting.
func NewHTTPSynthesizer(cfg Config) Synthesizer {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureTLS {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		} else {
			transport.TLSClientConfig.InsecureSkipVerify = true
		}
	}
	return &httpSynthesizer{
		cfg:    cfg,
		client: &http.Client{Transport: transport, Timeout: timeout},
	}
}

func (s *httpSynthesizer) Synthesize(ctx context.Context, digest SiteDigest) (*Policy, error) {
	if s.cfg.APIKey == "" {
		return nil, fmt.Errorf("ai: no API key configured")
	}
	req, err := s.buildRequest(ctx, digest.Compact())
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ai: %s returned %d: %s", s.cfg.provider(), resp.StatusCode, truncate(string(body), 200))
	}
	text, err := s.extractText(body)
	if err != nil {
		return nil, err
	}
	rules, err := parsePolicyRules(text)
	if err != nil {
		return nil, err
	}
	return Compile(rules), nil
}

// buildRequest constructs the provider-specific HTTP request.
func (s *httpSynthesizer) buildRequest(ctx context.Context, digest SiteDigest) (*http.Request, error) {
	digestJSON, err := json.Marshal(digest)
	if err != nil {
		return nil, err
	}
	user := userPrompt + "\n\nSITE DIGEST:\n" + string(digestJSON)

	var (
		urlStr  string
		payload []byte
	)
	switch s.cfg.provider() {
	case ProviderOpenAI:
		urlStr = s.cfg.baseURL() + "/v1/chat/completions"
		payload, err = json.Marshal(openAIRequest{
			Model:     s.cfg.model(),
			MaxTokens: 1024,
			Messages: []openAIMessage{
				{Role: "system", Content: systemPrompt},
				{Role: "user", Content: user},
			},
			ResponseFormat: &openAIResponseFormat{Type: "json_object"},
		})
	default:
		urlStr = s.cfg.baseURL() + "/v1/messages"
		payload, err = json.Marshal(anthropicRequest{
			Model:     s.cfg.model(),
			MaxTokens: 1024,
			System:    systemPrompt,
			Messages:  []anthropicMessage{{Role: "user", Content: user}},
		})
	}
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.provider() == ProviderOpenAI {
		req.Header.Set("Authorization", "Bearer "+s.cfg.APIKey)
	} else {
		req.Header.Set("x-api-key", s.cfg.APIKey)
		req.Header.Set("anthropic-version", anthropicVersion)
	}
	return req, nil
}

// extractText pulls the assistant text out of a provider response body.
func (s *httpSynthesizer) extractText(body []byte) (string, error) {
	if s.cfg.provider() == ProviderOpenAI {
		var r openAIResponse
		if err := json.Unmarshal(body, &r); err != nil {
			return "", fmt.Errorf("ai: decode openai response: %w", err)
		}
		if len(r.Choices) == 0 {
			return "", fmt.Errorf("ai: openai response had no choices")
		}
		return r.Choices[0].Message.Content, nil
	}
	var r anthropicResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("ai: decode anthropic response: %w", err)
	}
	var sb strings.Builder
	for _, blk := range r.Content {
		if blk.Type == "text" {
			sb.WriteString(blk.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("ai: anthropic response had no text content")
	}
	return sb.String(), nil
}

// parsePolicyRules robustly extracts the policy rules from a model reply that may
// wrap the JSON in prose or markdown fences.
func parsePolicyRules(text string) ([]Rule, error) {
	raw := extractJSONObject(text)
	if raw == "" {
		return nil, fmt.Errorf("ai: no JSON object found in model reply")
	}
	var wp wirePolicy
	if err := json.Unmarshal([]byte(raw), &wp); err != nil {
		return nil, fmt.Errorf("ai: parse policy JSON: %w", err)
	}
	return wp.Rules, nil
}

// extractJSONObject returns the substring from the first '{' to the last '}',
// after stripping any markdown code fences, or "" if none is present.
func extractJSONObject(text string) string {
	text = strings.ReplaceAll(text, "```json", "")
	text = strings.ReplaceAll(text, "```", "")
	start := strings.IndexByte(text, '{')
	end := strings.LastIndexByte(text, '}')
	if start < 0 || end <= start {
		return ""
	}
	return text[start : end+1]
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ---- provider wire types ----

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

type openAIRequest struct {
	Model          string                `json:"model"`
	MaxTokens      int                   `json:"max_tokens"`
	Messages       []openAIMessage       `json:"messages"`
	ResponseFormat *openAIResponseFormat `json:"response_format,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponseFormat struct {
	Type string `json:"type"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}
