package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/cxcompat"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestCXModelsUsesNativeCodexTransport(t *testing.T) {
	for _, tc := range []struct {
		name        string
		path        string
		header      string
		wantVersion string
		wantRaw     bool
	}{
		{name: "explicit query preserves raw catalog", path: "/v1/models?client_version=1.2.3", wantVersion: "1.2.3", wantRaw: true},
		{name: "version header wraps catalog", path: "/v1/models", header: "1.2.3", wantVersion: "1.2.3"},
		{name: "default wraps catalog", path: "/v1/models", wantVersion: "0.163.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			cxWriteCanonicalFixture(t, home, "models@example.test", true)
			setCXFixtureAccountID(t, home, "models@example.test", "stored-account-id")
			server := cxTestServer(t, true)
			server.cfg.CXCompatibility.SourceHome = home
			catalog := `{"models":[{"slug":"gpt-6-luna"}],"untouched":{"x":1}}`
			var calls int
			server.handlers.AuthManager.SetRoundTripperProvider(cxNativeTransportProvider{transport: cxNativeRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.String() != "https://chatgpt.com/backend-api/codex/models?client_version="+tc.wantVersion {
					t.Errorf("upstream URL = %q", req.URL.String())
				}
				if req.Header.Get("Authorization") != "Bearer synthetic-models@example.test" {
					t.Errorf("upstream Authorization = %q", req.Header.Get("Authorization"))
				}
				if req.Header.Get("Chatgpt-Account-Id") != "stored-account-id" {
					t.Errorf("account ID = %q", req.Header.Get("Chatgpt-Account-Id"))
				}
				if req.Header.Get("X-Client-Secret") != "" {
					t.Error("downstream-only header was forwarded")
				}
				if req.Header.Get("X-Codex-Turn-Metadata") != "safe-value" {
					t.Errorf("allowlisted CX header missing: %q", req.Header.Get("X-Codex-Turn-Metadata"))
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}, "X-Request-Id": []string{"catalog-request"}},
					Body:       io.NopCloser(strings.NewReader(catalog)),
					Request:    req,
				}, nil
			})})
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("Authorization", "Bearer downstream-secret")
			req.Header.Set("X-Client-Secret", "must-not-forward")
			req.Header.Set("X-Codex-Turn-Metadata", "safe-value")
			if tc.header != "" {
				req.Header.Set("Version", tc.header)
			}
			rr := httptest.NewRecorder()
			server.engine.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", rr.Code, rr.Body.String())
			}
			if calls != 1 {
				t.Fatalf("upstream calls = %d, want 1", calls)
			}
			if rr.Header().Get("X-Request-Id") != "catalog-request" {
				t.Fatalf("X-Request-Id = %q", rr.Header().Get("X-Request-Id"))
			}
			if tc.wantRaw {
				if rr.Body.String() != catalog {
					t.Fatalf("raw catalog = %s, want unchanged %s", rr.Body.String(), catalog)
				}
			} else if got, want := rr.Body.String(), `{"object":"list","data":[{"id":"gpt-6-luna","object":"model","owned_by":"openai"}]}`; got != want {
				t.Fatalf("model list = %s, want %s", got, want)
			}
			if entries, err := os.ReadDir(server.cfg.AuthDir); err != nil || len(entries) != 0 {
				t.Fatalf("native auth store changed: %v, %v", entries, err)
			}
		})
	}
}

func TestCXModelsRejectsMalformedCatalog(t *testing.T) {
	home := t.TempDir()
	cxWriteCanonicalFixture(t, home, "models@example.test", true)
	server := cxTestServer(t, true)
	server.cfg.CXCompatibility.SourceHome = home
	server.handlers.AuthManager.SetRoundTripperProvider(cxNativeTransportProvider{transport: cxNativeRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"models":{}}`)), Request: req}, nil
	})})
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), `"error"`) {
		t.Fatalf("HTTP %d, body %s; want OpenAI-shaped 502", rr.Code, rr.Body.String())
	}
}

func TestCXModels401RetriesSameAccountThenFallsBack(t *testing.T) {
	home := t.TempDir()
	cxWriteCanonicalFixture(t, home, "active@example.test", true)
	cxWriteCanonicalFixture(t, home, "other@example.test", false)
	server := cxTestServer(t, true)
	server.cfg.CXCompatibility.SourceHome = home
	active, err := cxcompat.NewStore(home).Account("active@example.test")
	if err != nil {
		t.Fatal(err)
	}
	other, err := cxcompat.NewStore(home).Account("other@example.test")
	if err != nil {
		t.Fatal(err)
	}
	activeID := helps.CXAccountAuth(home, active).ID
	otherID := helps.CXAccountAuth(home, other).ID
	capture := &cxExecutionCaptureExecutor{response: coreexecutor.Response{Payload: []byte(`{"object":"list","data":[]}`)}}
	failing := &cxModelsRetryExecutor{cxExecutionCaptureExecutor: capture, failures: map[string]int{activeID: 2}}
	server.handlers.AuthManager.RegisterExecutor(failing)
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rr.Code, rr.Body.String())
	}
	want := []string{activeID, activeID, otherID}
	if len(capture.authIDs) != len(want) {
		t.Fatalf("auth attempts = %v, want %v", capture.authIDs, want)
	}
	for i := range want {
		if capture.authIDs[i] != want[i] {
			t.Fatalf("auth attempts = %v, want %v", capture.authIDs, want)
		}
	}
	if capture.refreshCalls != 1 {
		t.Fatalf("same-account refresh calls = %d, want 1", capture.refreshCalls)
	}
}

type cxModelsRetryExecutor struct {
	*cxExecutionCaptureExecutor
	failures map[string]int
}

func (e *cxModelsRetryExecutor) Execute(ctx context.Context, selected *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	e.cxExecutionCaptureExecutor.authIDs = append(e.cxExecutionCaptureExecutor.authIDs, selected.ID)
	e.cxExecutionCaptureExecutor.calls++
	if e.failures[selected.ID] > 0 {
		e.failures[selected.ID]--
		return coreexecutor.Response{}, cxExecutionStatusError{status: http.StatusUnauthorized}
	}
	return e.cxExecutionCaptureExecutor.response, nil
}

func TestCXModels500DoesNotFailOver(t *testing.T) {
	home := t.TempDir()
	cxWriteCanonicalFixture(t, home, "active@example.test", true)
	cxWriteCanonicalFixture(t, home, "other@example.test", false)
	server := cxTestServer(t, true)
	server.cfg.CXCompatibility.SourceHome = home
	calls := 0
	server.handlers.AuthManager.SetRoundTripperProvider(cxNativeTransportProvider{transport: cxNativeRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusInternalServerError, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":{"message":"failed"}}`)), Request: req}, nil
	})})
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError || calls != 1 {
		t.Fatalf("HTTP %d after %d upstream calls: %s", rr.Code, calls, rr.Body.String())
	}
}

func setCXFixtureAccountID(t *testing.T, home, email, accountID string) {
	t.Helper()
	path := filepath.Join(home, ".codex-accounts", "accounts", email+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	auth, ok := record["auth"].(map[string]any)
	if !ok {
		t.Fatal("fixture auth is missing")
	}
	tokens, ok := auth["tokens"].(map[string]any)
	if !ok {
		t.Fatal("fixture tokens are missing")
	}
	tokens["account_id"] = accountID
	data, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
