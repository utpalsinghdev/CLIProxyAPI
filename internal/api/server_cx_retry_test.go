package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
)

// Exercise the real handler, account plan, executor and SSE translator with synthetic credentials.
func TestCXCanonicalTransientRecovery(t *testing.T) {
	const completed = "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-retry\",\"status\":\"completed\",\"output\":[]}}\n\n"
	const created = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-first\"}}\n\n"
	const delta = "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n"
	const tool = "event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"item\":{\"type\":\"web_search_call\",\"status\":\"in_progress\"}}\n\n"
	const failed = "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"error\":{\"status_code\":503,\"message\":\"upstream failed\"}}}\n\n"
	for _, tc := range []struct {
		name       string
		path       string
		body       string
		failure    string
		status     int
		retries    int
		persistent bool
		warm       bool
		unbuffered bool
		wantStatus int
		wantCalls  int
		wantDone   bool
	}{
		{name: "503 before headers", status: 503, retries: 2, wantStatus: 200, wantCalls: 2, wantDone: true},
		{name: "502 before headers", status: 502, retries: 2, wantStatus: 200, wantCalls: 2, wantDone: true},
		{name: "504 before headers", status: 504, retries: 2, wantStatus: 200, wantCalls: 2, wantDone: true},
		{name: "JSON request 503", status: 503, retries: 2, body: `{"model":"gpt-6-luna","input":"hello","stream":false}`, wantStatus: 200, wantCalls: 2, wantDone: true},
		{name: "closed bootstrap", failure: created, status: 200, retries: 2, wantStatus: 200, wantCalls: 2, wantDone: true},
		{name: "reset bootstrap", failure: created, status: 200, retries: 2, path: "reset", wantStatus: 200, wantCalls: 2, wantDone: true},
		{name: "partial text is not replayed", failure: created + delta, status: 200, retries: 2, wantStatus: 200, wantCalls: 1},
		{name: "server tool is not replayed", failure: created + tool, status: 200, retries: 2, wantStatus: 200, wantCalls: 1},
		{name: "JSON failure after tool is not replayed", body: `{"model":"gpt-6-luna","input":"hello","stream":false}`, failure: created + tool + failed, status: 200, retries: 2, wantStatus: 503, wantCalls: 1},
		{name: "JSON partial output is not replayed", body: `{"model":"gpt-6-luna","input":"hello","stream":false}`, failure: created + delta, status: 200, retries: 2, wantStatus: 408, wantCalls: 1},
		{name: "released handshake is not replayed", failure: created, status: 200, retries: 2, unbuffered: true, wantStatus: 200, wantCalls: 1},
		{name: "retry budget", status: 503, retries: 2, persistent: true, wantStatus: 503, wantCalls: 3},
		{name: "explicitly disabled", status: 503, retries: 0, wantStatus: 503, wantCalls: 1},
		{name: "warming never retries", status: 503, retries: 2, warm: true, body: cxWarmBody, wantStatus: 503, wantCalls: 1},
		{name: "policy denial never retries", status: 403, retries: 2, wantStatus: 403, wantCalls: 1},
		{name: "ordinary rate limit never retries", status: 429, retries: 2, wantStatus: 429, wantCalls: 1},
		{name: "uncertain POST transport never retries", path: "transport", retries: 2, wantStatus: 500, wantCalls: 1},
		{name: "cancelled POST never retries", path: "cancel", retries: 2, wantStatus: 499, wantCalls: 1},
		{name: "models GET transport recovery", path: "/v1/models?client_version=0.163.0", retries: 2, wantStatus: 200, wantCalls: 2, wantDone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			cxWriteCanonicalFixture(t, home, "retry@example.test", true)
			cxWriteCanonicalFixture(t, home, "other@example.test", false)
			server := cxTestServer(t, true)
			server.cfg.CXCompatibility.SourceHome = home
			server.cfg.RequestRetry = tc.retries
			server.cfg.Codex.StreamBootstrapBuffering = !tc.unbuffered
			server.handlers.AuthManager.RegisterExecutor(executor.NewCodexAutoExecutor(server.cfg))
			calls := 0
			var firstBody string
			server.handlers.AuthManager.SetRoundTripperProvider(cxNativeTransportProvider{transport: cxNativeRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Header.Get("Authorization") != "Bearer synthetic-retry@example.test" {
					t.Error("retry changed the selected account")
				}
				if req.Body != nil {
					body, err := io.ReadAll(req.Body)
					if err != nil {
						return nil, err
					}
					if calls == 1 {
						firstBody = string(body)
					} else if string(body) != firstBody {
						t.Error("retry changed the upstream request body")
					}
				}
				status, payload := http.StatusOK, completed
				if req.Method == http.MethodGet {
					payload = `{"models":[{"slug":"gpt-6-luna"}]}`
				}
				if calls == 1 || tc.persistent {
					if tc.path == "cancel" {
						return nil, context.Canceled
					}
					if tc.path == "transport" || req.Method == http.MethodGet {
						return nil, io.EOF
					}
					status, payload = tc.status, tc.failure
					if status != http.StatusOK {
						payload = "upstream connect error or disconnect/reset before headers. reset reason: connection termination"
					}
				}
				var body io.ReadCloser = io.NopCloser(strings.NewReader(payload))
				if calls == 1 && tc.path == "reset" {
					body = &cxResetBody{Reader: strings.NewReader(payload)}
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: body, Request: req}, nil
			})})
			path, method, body := "/v1/responses", http.MethodPost, tc.body
			if body == "" {
				body = `{"model":"gpt-6-luna","input":"hello","stream":true}`
			}
			if strings.HasPrefix(tc.path, "/v1/models") {
				path, method, body = tc.path, http.MethodGet, ""
			}
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("Content-Type", "application/json")
			if tc.warm {
				req.Header.Set(cxWarmHeader, "retry@example.test")
			}
			rr := httptest.NewRecorder()
			server.engine.ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Errorf("HTTP %d, want %d: %s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if calls != tc.wantCalls {
				t.Errorf("upstream attempts = %d, want %d", calls, tc.wantCalls)
			}
			done := strings.Contains(rr.Body.String(), `"type":"response.completed"`) || strings.Contains(rr.Body.String(), `"status":"completed"`) || strings.Contains(rr.Body.String(), `"models"`)
			if done != tc.wantDone {
				t.Errorf("completed = %v, want %v: %s", done, tc.wantDone, rr.Body.String())
			}
			if !tc.wantDone && tc.status == http.StatusOK && !strings.Contains(rr.Body.String(), `"error"`) {
				t.Errorf("truncated stream did not report an error: %s", rr.Body.String())
			}
		})
	}
}

type cxResetBody struct{ *strings.Reader }

func (b *cxResetBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (*cxResetBody) Close() error { return nil }
