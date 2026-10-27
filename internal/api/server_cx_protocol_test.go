package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

func TestCXCompatibilityPreservesNonCodexResponses(t *testing.T) {
	registry.GetGlobalRegistry().RegisterClient("cx-non-codex-fixture", "claude", []*registry.ModelInfo{{ID: "claude-cx-protocol-fixture"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient("cx-non-codex-fixture") })
	// Unknown routes may be handled by a plugin, so they must also pass through unchanged.
	for _, model := range []string{"claude-cx-protocol-fixture", "unknown-cx-plugin-fixture"} {
		t.Run(model, func(t *testing.T) {
			server := cxTestServer(t, true)
			body := `{ "model": "` + model + `", "input": "hello", "max_output_tokens": 20, "temperature": 0.5, "previous_response_id": "resp_previous" }`
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
			rr := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rr)
			c.Request = req
			if !server.cxPrepareResponses(c, false) {
				t.Fatalf("non-Codex request rejected: %s", rr.Body.String())
			}
			got, err := io.ReadAll(c.Request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != body {
				t.Fatalf("non-Codex request changed: %s", got)
			}
		})
	}
}

func TestCXHealthFollowsConfigReload(t *testing.T) {
	server := cxTestServer(t, false)
	for _, enabled := range []bool{false, true, false} {
		server.cfg.CXCompatibility.Enabled = enabled
		rr := httptest.NewRecorder()
		server.engine.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
		want := http.StatusNotFound
		if enabled {
			want = http.StatusOK
		}
		if rr.Code != want {
			t.Fatalf("enabled=%v: HTTP %d, want %d", enabled, rr.Code, want)
		}
	}
}
