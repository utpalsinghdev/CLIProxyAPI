package auth

import (
	"context"
	"net/http"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestRequestAuthPlanAuthBlockClearsWhenSnapshotTokenRotates(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	calls := 0
	executor := &requestPlanExecutor{execute: func(*Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		calls++
		if calls == 1 {
			return cliproxyexecutor.Response{}, requestPlanStatusError{status: http.StatusUnauthorized}
		}
		return cliproxyexecutor.Response{Payload: []byte("ok")}, nil
	}}
	manager.RegisterExecutor(executor)
	registered, err := manager.Register(context.Background(), &Auth{ID: "rotating-plan", Provider: "codex", Status: StatusActive, Attributes: map[string]string{"access_token": "old"}})
	if err != nil {
		t.Fatal(err)
	}
	makeContext := func(token string) context.Context {
		snapshot := registered.Clone()
		snapshot.Attributes["access_token"] = token
		return WithRequestAuthPlan(context.Background(), RequestAuthPlan{Auths: []*Auth{snapshot}, Model: "gpt-6-luna"})
	}
	if _, err := manager.Execute(makeContext("old"), []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}); err == nil {
		t.Fatal("first Execute() error = nil, want 401")
	}
	response, err := manager.Execute(makeContext("rotated"), []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if err != nil || string(response.Payload) != "ok" || calls != 2 {
		t.Fatalf("rotated token result=%q error=%v calls=%d", response.Payload, err, calls)
	}
}

func TestRequestAuthPlanPlain429DoesNotBlockAcrossRequests(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	calls := 0
	executor := &requestPlanExecutor{execute: func(*Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		calls++
		return cliproxyexecutor.Response{}, requestPlanStatusError{status: http.StatusTooManyRequests}
	}}
	manager.RegisterExecutor(executor)
	registered, err := manager.Register(context.Background(), &Auth{ID: "ordinary-429", Provider: "codex", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRequestAuthPlan(context.Background(), RequestAuthPlan{Auths: []*Auth{registered}, Model: "gpt-6-luna"})
	for range 2 {
		if _, err := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}); err == nil {
			t.Fatal("Execute() error = nil, want 429")
		}
	}
	if calls != 2 {
		t.Fatalf("attempts=%d, want retry on next request", calls)
	}
}
