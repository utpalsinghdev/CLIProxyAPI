package auth

import (
	"context"
	"net/http"
	"strings"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestRequestAuthPlanTransientRetryRefreshesOnlyOnce(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		name := "JSON"
		if streaming {
			name = "SSE"
		}
		t.Run(name, func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			attempts, refreshes := 0, 0
			nextError := func() error {
				attempts++
				if attempts == 2 {
					return requestPlanStatusError{status: http.StatusServiceUnavailable}
				}
				return requestPlanStatusError{status: http.StatusUnauthorized}
			}
			executor := &requestPlanExecutor{
				execute: func(*Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
					return cliproxyexecutor.Response{}, nextError()
				},
				stream: func(*Auth) (*cliproxyexecutor.StreamResult, error) {
					return nil, nextError()
				},
				refresh: func(auth *Auth) (*Auth, error) {
					refreshes++
					updated := auth.Clone()
					updated.Metadata["access_token"] = "refreshed"
					return updated, nil
				},
			}
			manager.RegisterExecutor(executor)
			auth, err := manager.Register(context.Background(), &Auth{ID: "retry-refresh", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"refresh_token": "synthetic"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx := WithRequestAuthPlan(context.Background(), RequestAuthPlan{
				Auths: []*Auth{auth}, Model: "gpt-6-luna", RetryLimit: 2,
				AllowRetry: func(err error) bool { return statusCodeFromError(err) == http.StatusServiceUnavailable },
			})
			if streaming {
				_, err = manager.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
			} else {
				_, err = manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
			}
			if statusCodeFromError(err) != http.StatusUnauthorized || attempts != 3 || refreshes != 1 {
				t.Fatalf("error=%v attempts=%d refreshes=%d, want 401 after 3 attempts and 1 refresh", err, attempts, refreshes)
			}
		})
	}
}

func TestRequestAuthPlanFailureLogsSafeDiagnostic(t *testing.T) {
	hook := setupTestLoggerHook(t)
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(&requestPlanExecutor{execute: func(*Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		return cliproxyexecutor.Response{}, markedDiagnosticStatusError{
			message: "upstream disconnected", statusCode: http.StatusServiceUnavailable,
			diagnostic: "upstream reset: access_token=synthetic-secret\nforged line",
		}
	}})
	auth, err := manager.Register(context.Background(), &Auth{ID: "log-retry", Provider: "codex", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRequestAuthPlan(context.Background(), RequestAuthPlan{Auths: []*Auth{auth}, Model: "gpt-6-luna"})
	_, err = manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if err == nil {
		t.Fatal("expected upstream failure")
	}
	entry := hook.LastEntry()
	if entry == nil || !strings.Contains(entry.Message, "CX upstream execution failed: upstream reset:") {
		t.Fatalf("missing failure diagnostic: %#v", entry)
	}
	if strings.Contains(entry.Message, "synthetic-secret") || strings.ContainsAny(entry.Message, "\r\n") {
		t.Fatalf("unsafe log message: %q", entry.Message)
	}
	if entry.Data["provider"] != "codex" || entry.Data["model"] != "gpt-6-luna" || entry.Data["status"] != http.StatusServiceUnavailable {
		t.Fatalf("missing failure fields: %#v", entry.Data)
	}
	hook.Reset()
	manager.recordRequestPlanResult(ctx, auth, Result{}, context.Canceled)
	if entry := hook.LastEntry(); entry != nil {
		t.Fatalf("client cancellation logged as upstream failure: %#v", entry)
	}
}
