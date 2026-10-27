package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestCXWarmExecutesPinnedResponsesRequest(t *testing.T) {
	ginSetModeForCX(t)
	server := cxTestServer(t, true)
	executor := &cxExecutionCaptureExecutor{
		response: coreexecutor.Response{Payload: []byte(`{"id":"resp-warm","object":"response","status":"completed","output":[]}`)},
	}
	server.handlers.AuthManager.RegisterExecutor(executor)

	// Register non-target first so ordinary account ordering cannot satisfy the pin.
	registerCXExecutionAccount(t, server, "other-auth", "other@example.com")
	registerCXExecutionAccount(t, server, "target-auth", "target@example.com")

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(cxWarmBody))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(cxWarmHeader, "target@example.com")
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if got, want := rr.Body.String(), `{"id":"resp-warm","object":"response","status":"completed","output":[]}`; got != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(executor.authIDs, []string{"target-auth"}) {
		t.Fatalf("executed auth IDs = %v, want [target-auth]", executor.authIDs)
	}
	if got, want := string(executor.payload), `{"include":["reasoning.encrypted_content"],"input":[{"content":[{"text":"Reply with OK only.","type":"input_text"}],"role":"user"}],"instructions":"","model":"gpt-6-luna","parallel_tool_calls":true,"reasoning":{"effort":"low"},"store":false,"stream":false}`; got != want {
		t.Fatalf("upstream payload = %q, want %q", got, want)
	}
	if executor.headers.Get(cxWarmHeader) != "" {
		t.Fatalf("targeting header forwarded upstream: %q", executor.headers.Get(cxWarmHeader))
	}
	if executor.refreshCalls != 0 {
		t.Fatalf("refresh calls = %d, want 0", executor.refreshCalls)
	}
	assertCXAuthUnchanged(t, server, "other-auth", "other@example.com")
}

func TestCXWarmUpstreamErrorsNeverFallbackToOtherAccount(t *testing.T) {
	for _, tt := range []struct {
		name        string
		statuses    []int
		wantStatus  int
		wantIDs     []string
		wantRefresh int
	}{
		{name: "rate limited", statuses: []int{http.StatusTooManyRequests}, wantStatus: http.StatusTooManyRequests, wantIDs: []string{"target-auth"}},
		{name: "unauthorized does not fallback or replay", statuses: []int{http.StatusUnauthorized}, wantStatus: http.StatusUnauthorized, wantIDs: []string{"target-auth"}},
		{name: "server error", statuses: []int{http.StatusInternalServerError}, wantStatus: http.StatusInternalServerError, wantIDs: []string{"target-auth"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ginSetModeForCX(t)
			server := cxTestServer(t, true)
			executor := &cxExecutionCaptureExecutor{statuses: tt.statuses}
			server.handlers.AuthManager.RegisterExecutor(executor)
			registerCXExecutionAccount(t, server, "other-auth", "other@example.com")
			registerCXExecutionAccount(t, server, "target-auth", "target@example.com")

			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(cxWarmBody))
			req.RemoteAddr = "127.0.0.1:4321"
			req.Header.Set("Authorization", "Bearer test-key")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(cxWarmHeader, "target@example.com")
			rr := httptest.NewRecorder()
			server.engine.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if !reflect.DeepEqual(executor.authIDs, tt.wantIDs) {
				t.Fatalf("executed auth IDs = %v, want %v", executor.authIDs, tt.wantIDs)
			}
			if executor.refreshCalls != tt.wantRefresh {
				t.Fatalf("refresh calls = %d, want %d", executor.refreshCalls, tt.wantRefresh)
			}
			if executor.calls != len(tt.wantIDs) {
				t.Fatalf("executor calls = %d, want %d", executor.calls, len(tt.wantIDs))
			}
			if executor.headers.Get(cxWarmHeader) != "" {
				t.Fatalf("targeting header forwarded upstream: %q", executor.headers.Get(cxWarmHeader))
			}
			assertCXAuthUnchanged(t, server, "other-auth", "other@example.com")
		})
	}
}

func TestCXWarmRejectsNonLoopbackEvenWithForwardedLoopbackAndDisabledHeader(t *testing.T) {
	for _, tt := range []struct {
		name       string
		enabled    bool
		remote     string
		forwarded  string
		wantStatus int
	}{
		{name: "forwarded loopback does not authorize remote", enabled: true, remote: "192.0.2.10:1234", forwarded: "127.0.0.1", wantStatus: http.StatusForbidden},
		{name: "disabled", enabled: false, remote: "127.0.0.1:1234", forwarded: "127.0.0.1", wantStatus: http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ginSetModeForCX(t)
			server := cxTestServer(t, tt.enabled)
			executor := &cxExecutionCaptureExecutor{}
			server.handlers.AuthManager.RegisterExecutor(executor)
			registerCXExecutionAccount(t, server, "target-auth", "target@example.com")
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(cxWarmBody))
			req.RemoteAddr = tt.remote
			req.Header.Set("X-Forwarded-For", tt.forwarded)
			req.Header.Set(cxWarmHeader, "target@example.com")
			rr := httptest.NewRecorder()
			server.engine.ServeHTTP(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if len(executor.authIDs) != 0 {
				t.Fatalf("executor auth IDs = %v, want no execution", executor.authIDs)
			}
		})
	}
}

type cxExecutionCaptureExecutor struct {
	authIDs      []string
	payload      []byte
	headers      http.Header
	statuses     []int
	calls        int
	refreshCalls int
	response     coreexecutor.Response
}

func (*cxExecutionCaptureExecutor) Identifier() string { return "codex" }

func (e *cxExecutionCaptureExecutor) Execute(_ context.Context, selected *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	e.authIDs = append(e.authIDs, selected.ID)
	e.payload = append([]byte(nil), req.Payload...)
	e.headers = opts.Headers.Clone()
	e.calls++
	if e.calls <= len(e.statuses) && e.statuses[e.calls-1] != http.StatusOK {
		return coreexecutor.Response{}, cxExecutionStatusError{status: e.statuses[e.calls-1]}
	}
	if len(e.statuses) > 0 {
		return coreexecutor.Response{}, cxExecutionStatusError{status: e.statuses[len(e.statuses)-1]}
	}
	return e.response, nil
}

func (*cxExecutionCaptureExecutor) ExecuteStream(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	return nil, errors.New("unexpected streaming execution")
}

func (e *cxExecutionCaptureExecutor) Refresh(_ context.Context, selected *coreauth.Auth) (*coreauth.Auth, error) {
	e.refreshCalls++
	return selected.Clone(), nil
}

func (*cxExecutionCaptureExecutor) CountTokens(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, errors.New("unexpected token count")
}

func (*cxExecutionCaptureExecutor) PrepareRequest(*http.Request, *coreauth.Auth) error { return nil }

func (*cxExecutionCaptureExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected raw HTTP execution")
}

type cxExecutionStatusError struct {
	status int
}

func (e cxExecutionStatusError) Error() string   { return fmt.Sprintf("upstream status %d", e.status) }
func (e cxExecutionStatusError) StatusCode() int { return e.status }

func registerCXExecutionAccount(t *testing.T, server *Server, id, email string) {
	t.Helper()
	registerCXAuth(t, server.handlers.AuthManager, id, email, "oauth")
	registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: "gpt-6-luna"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
}

func assertCXAuthUnchanged(t *testing.T, server *Server, id, email string) {
	t.Helper()
	for _, record := range server.handlers.AuthManager.List() {
		if record.ID != id {
			continue
		}
		if got, _ := record.Metadata["email"].(string); got != email {
			t.Fatalf("auth %s email = %q, want %q", id, got, email)
		}
		if got, _ := record.Attributes["auth_kind"]; got != "oauth" {
			t.Fatalf("auth %s kind = %q, want oauth", id, got)
		}
		if record.Disabled || record.Status != coreauth.StatusActive {
			t.Fatalf("auth %s disabled/status = %t/%q, want false/%q", id, record.Disabled, record.Status, coreauth.StatusActive)
		}
		return
	}
	t.Fatalf("auth %s missing after request", id)
}

func ginSetModeForCX(t *testing.T) {
	t.Helper()
	gin.SetMode(gin.TestMode)
}
