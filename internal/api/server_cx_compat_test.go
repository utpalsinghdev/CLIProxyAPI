package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestCXWarmRequestValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name, method, path, body, remote, origin, fetchSite string
		headerValues                                        []string
		wantStatus                                          int
		disabled                                            bool
		forwarded                                           string
		apiKeyAccount                                       bool
		ambiguous                                           bool
	}{
		{name: "valid pinned request", method: http.MethodPost, path: "/v1/responses", body: cxWarmBody, remote: "127.0.0.1:1234", headerValues: []string{"account@example.com"}, wantStatus: http.StatusOK},
		{name: "disabled config rejects header", method: http.MethodPost, path: "/v1/responses", body: cxWarmBody, remote: "127.0.0.1:1", headerValues: []string{"account@example.com"}, wantStatus: http.StatusForbidden, disabled: true},
		{name: "empty header", method: http.MethodPost, path: "/v1/responses", body: cxWarmBody, remote: "127.0.0.1:1", headerValues: []string{""}, wantStatus: http.StatusBadRequest},
		{name: "multiple headers", method: http.MethodPost, path: "/v1/responses", body: cxWarmBody, remote: "127.0.0.1:1", headerValues: []string{"account@example.com", "other@example.com"}, wantStatus: http.StatusBadRequest},
		{name: "untrusted forwarded address", method: http.MethodPost, path: "/v1/responses", body: cxWarmBody, remote: "192.0.2.1:1234", headerValues: []string{"account@example.com"}, wantStatus: http.StatusForbidden, forwarded: "127.0.0.1"},
		{name: "origin rejected", method: http.MethodPost, path: "/v1/responses", body: cxWarmBody, remote: "127.0.0.1:1", headerValues: []string{"account@example.com"}, origin: "https://evil.example", wantStatus: http.StatusForbidden},
		{name: "cross-site rejected", method: http.MethodPost, path: "/v1/responses", body: cxWarmBody, remote: "127.0.0.1:1", headerValues: []string{"account@example.com"}, fetchSite: "cross-site", wantStatus: http.StatusForbidden},
		{name: "extra body key", method: http.MethodPost, path: "/v1/responses", body: strings.TrimSuffix(cxWarmBody, "}") + `,"extra":true}`, remote: "127.0.0.1:1", headerValues: []string{"account@example.com"}, wantStatus: http.StatusBadRequest},
		{name: "null stream rejected", method: http.MethodPost, path: "/v1/responses", body: strings.Replace(cxWarmBody, `"stream":false`, `"stream":null`, 1), remote: "127.0.0.1:1", headerValues: []string{"account@example.com"}, wantStatus: http.StatusBadRequest},
		{name: "wrong method", method: http.MethodGet, path: "/v1/responses", body: cxWarmBody, remote: "127.0.0.1:1", headerValues: []string{"account@example.com"}, wantStatus: http.StatusMethodNotAllowed},
		{name: "wrong path", method: http.MethodPost, path: "/v1/chat/completions", body: cxWarmBody, remote: "127.0.0.1:1", headerValues: []string{"account@example.com"}, wantStatus: http.StatusBadRequest},
		{name: "unknown account", method: http.MethodPost, path: "/v1/responses", body: cxWarmBody, remote: "127.0.0.1:1", headerValues: []string{"missing@example.com"}, wantStatus: http.StatusNotFound},
		{name: "API key account rejected", method: http.MethodPost, path: "/v1/responses", body: cxWarmBody, remote: "127.0.0.1:1", headerValues: []string{"key@example.com"}, wantStatus: http.StatusNotFound, apiKeyAccount: true},
		{name: "ambiguous account rejected", method: http.MethodPost, path: "/v1/responses", body: cxWarmBody, remote: "127.0.0.1:1", headerValues: []string{"account@example.com"}, wantStatus: http.StatusNotFound, ambiguous: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := cxTestServer(t, !tt.disabled)
			registerCXAuth(t, server.handlers.AuthManager, "auth-one", "account@example.com", "oauth")
			if tt.apiKeyAccount {
				registerCXAuth(t, server.handlers.AuthManager, "api-key", "key@example.com", "apikey")
			}
			if tt.ambiguous {
				registerCXAuth(t, server.handlers.AuthManager, "auth-two", "account@example.com", "oauth")
			}
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.RemoteAddr = tt.remote
			req.Header[http.CanonicalHeaderKey(cxWarmHeader)] = append([]string(nil), tt.headerValues...)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.fetchSite)
			}
			if tt.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tt.forwarded)
			}
			var bodyAfterMiddleware []byte
			engine := gin.New()
			engine.Use(server.cxCompatibilityMiddleware())
			engine.Any("/*path", func(c *gin.Context) {
				if c.Request.Header.Get(cxWarmHeader) != "" {
					t.Error("targeting header reached handler")
				}
				bodyAfterMiddleware, _ = io.ReadAll(c.Request.Body)
				c.Status(http.StatusOK)
			})
			rr := httptest.NewRecorder()
			engine.ServeHTTP(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if tt.name == "valid pinned request" {
				var normalized struct {
					Model  string `json:"model"`
					Stream bool   `json:"stream"`
					Input  []struct {
						Role string `json:"role"`
					} `json:"input"`
				}
				if err := json.Unmarshal(bodyAfterMiddleware, &normalized); err != nil || normalized.Model != "gpt-6-luna" || normalized.Stream || len(normalized.Input) != 1 || normalized.Input[0].Role != "user" {
					t.Fatalf("invalid normalized warm body: %s", bodyAfterMiddleware)
				}
			}
			if rr.Code >= 400 {
				var payload map[string]any
				if json.Unmarshal(rr.Body.Bytes(), &payload) != nil || payload["error"] == nil {
					t.Fatalf("error response not OpenAI-shaped: %s", rr.Body.String())
				}
			}
		})
	}
}

func TestCXHealthContainsOnlyCompatibilityFields(t *testing.T) {
	server := cxTestServer(t, true)
	registerCXAuth(t, server.handlers.AuthManager, "enabled-oauth", "private@example.com", "oauth")
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	want := `{"accounts":1,"status":"ok","targetedWarming":true}`
	if strings.TrimSpace(rr.Body.String()) != want {
		t.Fatalf("health response = %s, want %s", rr.Body.String(), want)
	}
	if bytes.Contains(rr.Body.Bytes(), []byte("private@example.com")) {
		t.Fatal("health leaked account metadata")
	}
}

func cxTestServer(t *testing.T, enabled bool) *Server {
	t.Helper()
	cfg := &config.Config{AuthDir: t.TempDir(), CXCompatibility: config.CXCompatibilityConfig{Enabled: enabled}}
	server := NewServer(cfg, coreauth.NewManager(nil, nil, nil), nil, t.TempDir())
	return server
}

func registerCXAuth(t *testing.T, manager *coreauth.Manager, id, email, kind string) {
	t.Helper()
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID: id, Provider: "codex", Status: coreauth.StatusActive,
		Attributes: map[string]string{"auth_kind": kind},
		Metadata:   map[string]any{"email": email, "auth_kind": kind},
	})
	if err != nil {
		t.Fatalf("register auth: %v", err)
	}
}
