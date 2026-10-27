package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

type cxNativeRoundTripper func(*http.Request) (*http.Response, error)

func (f cxNativeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type cxNativeTransportProvider struct{ transport http.RoundTripper }

func (p cxNativeTransportProvider) RoundTripperFor(*coreauth.Auth) http.RoundTripper {
	return p.transport
}

// This fixture runs the native HTTP executor and protocol translator without opening
// an upstream socket. No canonical auth file or production service participates.
func TestCXCanonicalNativeTransportReturnsCompletedJSON(t *testing.T) {
	home := t.TempDir()
	cxWriteCanonicalFixture(t, home, "native-fixture@example.test", true)
	server := cxTestServer(t, true)
	server.cfg.CXCompatibility.SourceHome = home
	server.handlers.AuthManager.RegisterExecutor(executor.NewCodexAutoExecutor(server.cfg))
	var calls int
	var upstream []byte
	server.handlers.AuthManager.SetRoundTripperProvider(cxNativeTransportProvider{transport: cxNativeRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.String() != "https://chatgpt.com/backend-api/codex/responses" {
			t.Errorf("unexpected upstream URL: %s", req.URL)
		}
		if req.Header.Get("Authorization") != "Bearer synthetic-native-fixture@example.test" {
			t.Error("native transport did not use canonical fixture credential")
		}
		if req.Header.Get(cxWarmHeader) != "" {
			t.Error("targeting header reached native HTTP transport")
		}
		var err error
		upstream, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		sse := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-native-fixture\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"gpt-6-luna\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"OK\"}]}],\"usage\":{\"input_tokens\":3,\"output_tokens\":1,\"total_tokens\":4}}}\n\n"
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(sse)), Request: req}, nil
	})})
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(cxWarmBody))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(cxWarmHeader, "native-fixture@example.test")
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rr.Code, rr.Body.String())
	}
	if calls != 1 {
		t.Fatalf("native HTTP calls=%d, want1", calls)
	}
	if gjson.Get(rr.Body.String(), "status").String() != "completed" || gjson.Get(rr.Body.String(), "output.0.content.0.text").String() != "OK" {
		t.Fatalf("wrong completed JSON: %s", rr.Body.String())
	}
	if gjson.GetBytes(upstream, "model").String() != "gpt-6-luna" {
		t.Fatalf("upstream model changed: %s", upstream)
	}
	if !gjson.GetBytes(upstream, "stream").Bool() || gjson.GetBytes(upstream, "store").Bool() {
		t.Fatalf("wrong upstream transport flags: %s", upstream)
	}
	if gjson.GetBytes(upstream, "tools").Exists() {
		t.Fatalf("CX warm unexpectedly acquired tools: %s", upstream)
	}
	if gjson.GetBytes(upstream, "prompt_cache_key").Exists() {
		t.Fatalf("CX warm unexpectedly acquired a generated cache key: %s", upstream)
	}
	if gjson.Get(rr.Body.String(), "usage.total_tokens").Int() != 4 {
		t.Fatalf("usage changed: %s", rr.Body.String())
	}
	// Exercise the separate native streaming transport with the same canonical source.
	streamBody := strings.Replace(cxWarmBody, `"stream":false`, `"stream":true`, 1)
	streamRequest := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(streamBody))
	streamRequest.RemoteAddr = "127.0.0.1:1234"
	streamRecorder := httptest.NewRecorder()
	server.engine.ServeHTTP(streamRecorder, streamRequest)
	if streamRecorder.Code != http.StatusOK || !strings.Contains(streamRecorder.Header().Get("Content-Type"), "text/event-stream") || !strings.Contains(streamRecorder.Body.String(), `"type":"response.completed"`) {
		t.Fatalf("native SSE failed: HTTP %d %s", streamRecorder.Code, streamRecorder.Body.String())
	}
	if calls != 2 {
		t.Fatalf("native JSON+SSE upstream calls=%d, want 2", calls)
	}
	if gjson.GetBytes(upstream, "tools").Exists() || gjson.GetBytes(upstream, "prompt_cache_key").Exists() {
		t.Fatalf("native SSE changed CX request shape: %s", upstream)
	}
}
