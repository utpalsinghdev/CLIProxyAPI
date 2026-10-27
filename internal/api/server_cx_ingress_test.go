package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

type cxRejectKeysProvider struct{}

func (cxRejectKeysProvider) Identifier() string { return "fixture" }
func (cxRejectKeysProvider) Authenticate(context.Context, *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	return nil, sdkaccess.NewNoCredentialsError()
}

func TestCXKeylessBoundaryDoesNotBypassNativeOrManagementAuth(t *testing.T) {
	for _, tt := range []struct {
		name, method, path, peer, forwarded string
		want                                int
	}{
		{"loopback models", "GET", "/v1/models", "127.0.0.1:1234", "", 204},
		{"tailnet responses", "POST", "/v1/responses", "100.115.188.50:1234", "", 204},
		{"tailnet v6 compact", "POST", "/v1/responses/compact", "[fd7a:115c:a1e0::1234]:1234", "", 204},
		{"LAN denied", "POST", "/v1/responses", "192.168.1.20:1234", "", 403},
		{"forged forwarded denied", "POST", "/v1/responses", "203.0.113.20:1234", "127.0.0.1", 403},
		{"native chat still keyed", "POST", "/v1/chat/completions", "127.0.0.1:1234", "", 401},
		{"websocket still keyed", "GET", "/v1/responses", "127.0.0.1:1234", "", 401},
		{"management still keyed", "GET", "/v0/management/auth-files", "127.0.0.1:1234", "", 401},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manager := sdkaccess.NewManager()
			manager.SetProviders([]sdkaccess.Provider{cxRejectKeysProvider{}})
			server := &Server{cfg: &config.Config{CXCompatibility: config.CXCompatibilityConfig{Enabled: true, SourceHome: t.TempDir(), ProtectedListeners: true, Keyless: true}}, accessManager: manager}
			engine := gin.New()
			engine.Use(server.cxAPIAuthMiddleware())
			engine.Any("/*path", func(c *gin.Context) { c.Status(http.StatusNoContent) })
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.RemoteAddr = tt.peer
			req.Header.Set("X-Forwarded-For", tt.forwarded)
			rr := httptest.NewRecorder()
			engine.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("HTTP %d, want %d: %s", rr.Code, tt.want, rr.Body.String())
			}
		})
	}
}

func TestCXIngressReloadCannotChangeStartupBoundary(t *testing.T) {
	for _, mutateInPlace := range []bool{false, true} {
		t.Run(map[bool]string{false: "new config", true: "shared config pointer"}[mutateInPlace], func(t *testing.T) {
			server := cxTestServer(t, false)
			cfg := &config.Config{CXCompatibility: config.CXCompatibilityConfig{Enabled: true, ProtectedListeners: true, Keyless: true, SourceHome: t.TempDir()}}
			if mutateInPlace {
				server.cfg.CXCompatibility = cfg.CXCompatibility
				cfg = server.cfg
			}
			if server.UpdateClientsContext(context.Background(), cfg) {
				t.Fatal("live reload changed protected/keyless startup boundary")
			}
			if server.cfg.CXCompatibility.Enabled || server.cfg.CXCompatibility.Keyless {
				t.Fatal("rejected reload left compatibility enabled")
			}
		})
	}
}

func TestCXKeylessUnsafeConfigurationRefused(t *testing.T) {
	for _, cfg := range []config.CXCompatibilityConfig{
		{Keyless: true},
		{Enabled: true},
		{Enabled: true, Keyless: true, SourceHome: t.TempDir()},
		{Enabled: true, Keyless: true, ProtectedListeners: true, SourceHome: "relative"},
		{ProtectedListeners: true},
	} {
		server := &Server{cfg: &config.Config{CXCompatibility: cfg}}
		if err := server.validateCXIngress(); err == nil {
			t.Fatalf("unsafe configuration accepted: %+v", cfg)
		}
	}
}
