package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type requestPlanExecutor struct {
	calls   []string
	models  []string
	execute func(*Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error)
	stream  func(*Auth) (*cliproxyexecutor.StreamResult, error)
	refresh func(*Auth) (*Auth, error)
}

func (e *requestPlanExecutor) Identifier() string { return "codex" }
func (e *requestPlanExecutor) Execute(_ context.Context, auth *Auth, req cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.calls = append(e.calls, auth.ID)
	e.models = append(e.models, req.Model)
	if e.execute != nil {
		return e.execute(auth, req)
	}
	return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
}
func (e *requestPlanExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if e.stream != nil {
		return e.stream(auth)
	}
	return nil, errors.New("unused")
}
func (e *requestPlanExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	if e.refresh != nil {
		return e.refresh(auth)
	}
	return nil, errors.New("unused")
}
func (*requestPlanExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, errors.New("unused")
}
func (*requestPlanExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("unused")
}

type requestPlanStatusError struct{ status int }

func (e requestPlanStatusError) Error() string            { return "upstream status" }
func (e requestPlanStatusError) StatusCode() int          { return e.status }
func (e requestPlanStatusError) IsCredentialScoped() bool { return true }

type requestPlanQuotaError struct {
	requestPlanStatusError
	body []byte
}

func (e requestPlanQuotaError) ResponseBody() []byte { return e.body }

func TestRequestAuthPlanFallbackKeepsOrderAndExactModel(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	executor := &requestPlanExecutor{execute: func(auth *Auth, req cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		if auth.ID == "plan-a" {
			return cliproxyexecutor.Response{}, requestPlanStatusError{status: http.StatusTooManyRequests}
		}
		return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
	}}
	manager.RegisterExecutor(executor)
	authA := &Auth{ID: "plan-a", Provider: "codex", Status: StatusActive}
	authB := &Auth{ID: "plan-b", Provider: "codex", Status: StatusActive}
	for _, auth := range []*Auth{authA, authB} {
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
	}
	ctx := WithRequestAuthPlan(context.Background(), RequestAuthPlan{
		Auths: []*Auth{authA, authB}, Model: "gpt-6-luna",
		AllowFallback: func(err error) bool { return isCredentialScopedError(err) },
	})
	response, err := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: "alias-model"}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Payload) != authB.ID {
		t.Fatalf("response = %q, want plan-b", response.Payload)
	}
	if got := len(executor.calls); got != 2 || executor.calls[0] != authA.ID || executor.calls[1] != authB.ID {
		t.Fatalf("attempts = %v", executor.calls)
	}
	for _, model := range executor.models {
		if model != "gpt-6-luna" {
			t.Fatalf("upstream model = %q, want exact plan model", model)
		}
	}
	updatedA, _ := manager.GetByID(authA.ID)
	updatedB, _ := manager.GetByID(authB.ID)
	if updatedA.Failed != 1 || updatedB.Success != 1 {
		t.Fatalf("result counters A=%d B=%d", updatedA.Failed, updatedB.Success)
	}
}

func TestRequestAuthPlanAllQuotaCooledReturns429(t *testing.T) {
	withQuotaCooldownEnabled(t)
	manager := NewManager(nil, nil, nil)
	calls := 0
	executor := &requestPlanExecutor{execute: func(*Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		calls++
		return cliproxyexecutor.Response{}, requestPlanQuotaError{requestPlanStatusError: requestPlanStatusError{status: http.StatusTooManyRequests}, body: []byte(`{"error":{"type":"usage_limit_reached","resets_in_seconds":45}}`)}
	}}
	manager.RegisterExecutor(executor)
	registered, err := manager.Register(context.Background(), &Auth{ID: "quota-cooled", Provider: "codex", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRequestAuthPlan(context.Background(), RequestAuthPlan{Auths: []*Auth{registered}, Model: "gpt-6-luna", AllowFallback: func(error) bool { return true }})
	_, firstErr := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if firstErr == nil {
		t.Fatal("first Execute() error = nil, want quota error")
	}
	_, secondErr := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if secondErr == nil || statusCodeFromError(secondErr) != http.StatusTooManyRequests {
		t.Fatalf("second Execute() error = %v, want quota 429", secondErr)
	}
	if calls != 1 {
		t.Fatalf("attempts = %d, want cooled account skipped", calls)
	}
	var retryErr interface {
		StatusCode() int
		RetryAfter() *time.Duration
		Headers() http.Header
	}
	if !errors.As(secondErr, &retryErr) || retryErr.StatusCode() != http.StatusTooManyRequests || retryErr.RetryAfter() == nil || *retryErr.RetryAfter() < 40*time.Second || retryErr.Headers().Get("Retry-After") == "" {
		t.Fatalf("all-cooled error = %#v, want quota 429 with reset retry hint", secondErr)
	}
	payload, err := json.Marshal(secondErr)
	if err != nil || !json.Valid(payload) || len(payload) == 0 || payload[0] != '{' {
		t.Fatalf("all-cooled JSON error = %s, marshal error=%v", payload, err)
	}
	var openAIShape map[string]json.RawMessage
	if err := json.Unmarshal(payload, &openAIShape); err != nil || openAIShape["error"] == nil {
		t.Fatalf("all-cooled JSON = %s, want OpenAI error envelope", payload)
	}
}

func TestRequestAuthPlanGenericFailureDoesNotCoolAccount(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	calls := 0
	executor := &requestPlanExecutor{execute: func(*Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		calls++
		return cliproxyexecutor.Response{}, requestPlanStatusError{status: http.StatusInternalServerError}
	}}
	manager.RegisterExecutor(executor)
	auth := &Auth{ID: "neutral-500", Provider: "codex", Status: StatusActive}
	registered, err := manager.Register(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRequestAuthPlan(context.Background(), RequestAuthPlan{Auths: []*Auth{registered}, Model: "gpt-6-luna"})
	for range 2 {
		if _, err := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}); err == nil {
			t.Fatal("Execute() error = nil, want upstream 500")
		}
	}
	if calls != 2 {
		t.Fatalf("attempts = %d, want account retried on next request", calls)
	}
}

func TestRequestAuthPlanDoesNotFallbackWithoutApproval(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetRetryConfig(5, 0, 0)
	executor := &requestPlanExecutor{execute: func(*Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		return cliproxyexecutor.Response{}, requestPlanStatusError{status: http.StatusTooManyRequests}
	}}
	manager.RegisterExecutor(executor)
	auths := []*Auth{{ID: "no-fallback-a", Provider: "codex", Status: StatusActive}, {ID: "no-fallback-b", Provider: "codex", Status: StatusActive}}
	for _, auth := range auths {
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
	}
	ctx := WithRequestAuthPlan(context.Background(), RequestAuthPlan{Auths: auths, Model: "gpt-6-luna", AllowFallback: func(error) bool { return false }})
	_, err := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if err == nil {
		t.Fatal("Execute() error = nil, want quota error")
	}
	if len(executor.calls) != 1 || executor.calls[0] != auths[0].ID {
		t.Fatalf("attempts = %v, want first account only", executor.calls)
	}
}

func TestRequestAuthPlanRetriesUnauthorizedOnceBeforeFallback(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	attempts := map[string]int{}
	refreshes := 0
	executor := &requestPlanExecutor{
		execute: func(auth *Auth, _ cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
			attempts[auth.ID]++
			if auth.ID == "refresh-a" && attempts[auth.ID] == 1 {
				return cliproxyexecutor.Response{}, requestPlanStatusError{status: http.StatusUnauthorized}
			}
			if auth.ID == "refresh-a" {
				return cliproxyexecutor.Response{}, requestPlanStatusError{status: http.StatusTooManyRequests}
			}
			return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
		},
		refresh: func(auth *Auth) (*Auth, error) {
			refreshes++
			updated := auth.Clone()
			updated.Metadata["access_token"] = "refreshed"
			return updated, nil
		},
	}
	manager.RegisterExecutor(executor)
	auths := []*Auth{
		{ID: "refresh-a", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"refresh_token": "refresh"}},
		{ID: "refresh-b", Provider: "codex", Status: StatusActive},
	}
	for _, auth := range auths {
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
	}
	ctx := WithRequestAuthPlan(context.Background(), RequestAuthPlan{Auths: auths, Model: "gpt-6-luna", AllowFallback: func(err error) bool { return isCredentialScopedError(err) }})
	response, err := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Payload) != "refresh-b" || attempts["refresh-a"] != 2 || attempts["refresh-b"] != 1 || refreshes != 1 {
		t.Fatalf("payload=%q attempts=%v refreshes=%d", response.Payload, attempts, refreshes)
	}
}

func TestRequestAuthPlanRefreshesAttemptedPreparedAuth(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	var refreshedFrom string
	var attempts []string
	executor := &requestPlanExecutor{
		execute: func(auth *Auth, _ cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
			attempts = append(attempts, auth.Metadata["access_token"].(string))
			if len(attempts) == 1 {
				return cliproxyexecutor.Response{}, requestPlanStatusError{status: http.StatusUnauthorized}
			}
			return cliproxyexecutor.Response{Payload: []byte("ok")}, nil
		},
		refresh: func(auth *Auth) (*Auth, error) {
			refreshedFrom = auth.Metadata["access_token"].(string)
			updated := auth.Clone()
			updated.Metadata["access_token"] = "new-token"
			return updated, nil
		},
	}
	manager.RegisterExecutor(executor)
	registered, err := manager.Register(context.Background(), &Auth{ID: "prepared-refresh", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"access_token": "manager-old", "refresh_token": "refresh"}})
	if err != nil {
		t.Fatal(err)
	}
	attempted := registered.Clone()
	attempted.Metadata["access_token"] = "prepared-current"
	ctx := WithRequestAuthPlan(context.Background(), RequestAuthPlan{Auths: []*Auth{attempted}, Model: "gpt-6-luna"})
	if _, err := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}); err != nil {
		t.Fatal(err)
	}
	if refreshedFrom != "prepared-current" || len(attempts) != 2 || attempts[1] != "new-token" {
		t.Fatalf("refresh input=%q attempts=%v, want prepared-current then new-token", refreshedFrom, attempts)
	}
}

func TestRequestAuthPlanStreamFallbackOnlyBeforeFirstPayload(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	var calls []string
	executor := &requestPlanExecutor{stream: func(auth *Auth) (*cliproxyexecutor.StreamResult, error) {
		calls = append(calls, auth.ID)
		chunks := make(chan cliproxyexecutor.StreamChunk, 2)
		if auth.ID == "stream-a" {
			chunks <- cliproxyexecutor.StreamChunk{Err: requestPlanStatusError{status: http.StatusTooManyRequests}}
		} else {
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("first")}
			chunks <- cliproxyexecutor.StreamChunk{Err: requestPlanStatusError{status: http.StatusInternalServerError}}
		}
		close(chunks)
		return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
	}}
	manager.RegisterExecutor(executor)
	auths := []*Auth{{ID: "stream-a", Provider: "codex", Status: StatusActive}, {ID: "stream-b", Provider: "codex", Status: StatusActive}}
	for _, auth := range auths {
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
	}
	ctx := WithRequestAuthPlan(context.Background(), RequestAuthPlan{Auths: auths, Model: "gpt-6-luna", AllowFallback: func(error) bool { return true }})
	result, err := manager.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var got []cliproxyexecutor.StreamChunk
	for chunk := range result.Chunks {
		got = append(got, chunk)
	}
	if len(calls) != 2 || calls[0] != "stream-a" || calls[1] != "stream-b" {
		t.Fatalf("attempts = %v", calls)
	}
	if len(got) != 2 || string(got[0].Payload) != "first" || got[1].Err == nil {
		t.Fatalf("stream chunks = %+v", got)
	}
}

func TestRequestAuthPlanKeepsInFlightCredentialSnapshot(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	started, release := make(chan struct{}), make(chan struct{})
	executor := &requestPlanExecutor{execute: func(auth *Auth, _ cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		close(started)
		<-release
		return cliproxyexecutor.Response{Payload: []byte(auth.Attributes["access_token"])}, nil
	}}
	manager.RegisterExecutor(executor)
	auth := &Auth{ID: "held-request", Provider: "codex", Status: StatusActive, Attributes: map[string]string{"access_token": "snapshot-token"}}
	registered, err := manager.Register(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRequestAuthPlan(context.Background(), RequestAuthPlan{Auths: []*Auth{registered}, Model: "gpt-6-luna"})
	responseCh := make(chan cliproxyexecutor.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		response, errExecute := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
		responseCh <- response
		errCh <- errExecute
	}()
	<-started
	current, ok := manager.GetByID(auth.ID)
	if !ok {
		t.Fatal("registered auth disappeared")
	}
	current.Attributes["access_token"] = "rotated-token"
	if _, errUpdate := manager.Update(context.Background(), current); errUpdate != nil {
		t.Fatal(errUpdate)
	}
	close(release)
	response := <-responseCh
	if errExecute := <-errCh; errExecute != nil {
		t.Fatal(errExecute)
	}
	if string(response.Payload) != "snapshot-token" {
		t.Fatalf("in-flight token = %q, want frozen snapshot", response.Payload)
	}
}

func TestRequestAuthPlanCopiesAuthSnapshots(t *testing.T) {
	auth := &Auth{ID: "snapshot", Provider: "codex", Attributes: map[string]string{"access_token": "before"}}
	ctx := WithRequestAuthPlan(context.Background(), RequestAuthPlan{Auths: []*Auth{auth}, Model: "gpt-6-luna"})
	auth.Attributes["access_token"] = "after"
	plan, ok := RequestAuthPlanFromContext(ctx)
	if !ok || len(plan.Auths) != 1 || plan.Auths[0].Attributes["access_token"] != "before" {
		t.Fatalf("context plan did not retain snapshot: %+v", plan)
	}
	plan.Auths[0].Attributes["access_token"] = "mutated"
	again, _ := RequestAuthPlanFromContext(ctx)
	if again.Auths[0].Attributes["access_token"] != "before" {
		t.Fatal("retrieved plan mutated stored snapshot")
	}
}
