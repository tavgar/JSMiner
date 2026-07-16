package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testDigest() SiteDigest {
	return SiteDigest{
		Origin:    "https://x.test",
		Templates: []string{"x.test/api/v2/users", "x.test/product/{}"},
		Counts:    map[string]int{"x.test/api/v2/users": 1, "x.test/product/{}": 99},
		Levels:    []string{"/", "/api/"},
		Samples:   []string{"https://x.test/api/v2/users"},
	}
}

func TestSynthesizeAnthropicAdapter(t *testing.T) {
	var gotPath, gotKey, gotVersion, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"content":[{"type":"text","text":"{\"version\":1,\"rules\":[{\"pattern\":\"/api/\",\"weight\":80,\"reason\":\"api\"}]}"}]}`)
	}))
	defer srv.Close()

	syn := NewHTTPSynthesizer(Config{Enabled: true, Provider: ProviderAnthropic, BaseURL: srv.URL, APIKey: "sk-test", Model: "claude-haiku-4-5"})
	p, err := syn.Synthesize(context.Background(), testDigest())
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	if gotPath != "/v1/messages" {
		t.Errorf("path = %q, want /v1/messages", gotPath)
	}
	if gotKey != "sk-test" {
		t.Errorf("x-api-key = %q", gotKey)
	}
	if gotVersion != anthropicVersion {
		t.Errorf("anthropic-version = %q", gotVersion)
	}
	if !strings.Contains(gotBody, "api/v2/users") {
		t.Errorf("request body did not carry the digest: %s", gotBody)
	}
	if p.Len() != 1 || p.Bonus("https://x.test/api/data") != 80 {
		t.Errorf("policy not parsed from anthropic reply: len=%d", p.Len())
	}
}

func TestSynthesizeOpenAIAdapter(t *testing.T) {
	var gotPath, gotAuth string
	var reqBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&reqBody)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"version\":1,\"rules\":[{\"pattern\":\"/graphql\",\"weight\":70}]}"}}]}`)
	}))
	defer srv.Close()

	syn := NewHTTPSynthesizer(Config{Enabled: true, Provider: ProviderOpenAI, BaseURL: srv.URL, APIKey: "sk-oa", Model: "gpt-4o-mini"})
	p, err := syn.Synthesize(context.Background(), testDigest())
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("path = %q, want /v1/chat/completions", gotPath)
	}
	if gotAuth != "Bearer sk-oa" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if rf, _ := reqBody["response_format"].(map[string]any); rf["type"] != "json_object" {
		t.Errorf("expected json_object response_format, got %v", reqBody["response_format"])
	}
	if p.Len() != 1 || p.Bonus("https://x.test/graphql") != 70 {
		t.Errorf("policy not parsed from openai reply: len=%d", p.Len())
	}
}

func TestSynthesizeErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"bad key"}`)
	}))
	defer srv.Close()
	syn := NewHTTPSynthesizer(Config{Enabled: true, Provider: ProviderAnthropic, BaseURL: srv.URL, APIKey: "x"})
	if _, err := syn.Synthesize(context.Background(), testDigest()); err == nil {
		t.Error("expected error on 401")
	}
}

func TestSynthesizeErrorsWithoutKey(t *testing.T) {
	syn := NewHTTPSynthesizer(Config{Enabled: true, Provider: ProviderAnthropic})
	if _, err := syn.Synthesize(context.Background(), testDigest()); err == nil {
		t.Error("expected error when APIKey is empty")
	}
}

func TestConfigDefaults(t *testing.T) {
	if (Config{}).EffectiveModel() != defaultAnthropicModel {
		t.Errorf("default model = %q", (Config{}).EffectiveModel())
	}
	if (Config{Provider: ProviderOpenAI}).EffectiveModel() != defaultOpenAIModel {
		t.Errorf("openai default model = %q", (Config{Provider: ProviderOpenAI}).EffectiveModel())
	}
	if (Config{Provider: ProviderOpenAI}).baseURL() != defaultOpenAIBaseURL {
		t.Errorf("openai default base = %q", (Config{Provider: ProviderOpenAI}).baseURL())
	}
	if (Config{BaseURL: "https://gw.local/"}).baseURL() != "https://gw.local" {
		t.Errorf("trailing slash not trimmed: %q", (Config{BaseURL: "https://gw.local/"}).baseURL())
	}
}
