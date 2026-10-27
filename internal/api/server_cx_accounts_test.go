package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/cxcompat"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func cxWriteCanonicalFixture(t *testing.T, home, email string, active bool) {
	t.Helper()
	claims, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		t.Fatal(err)
	}
	id := "header." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
	auth := map[string]any{"tokens": map[string]string{"access_token": "synthetic-" + email, "refresh_token": "synthetic-refresh", "id_token": id}}
	record, err := json.Marshal(map[string]any{"email": email, "auth": auth})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".codex-accounts", "accounts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, email+".json"), record, 0o600); err != nil {
		t.Fatal(err)
	}
	if active {
		dir := filepath.Join(home, ".codex")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(auth)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "auth.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCXCanonicalRequestsFollowActiveABAWithoutModelAlias(t *testing.T) {
	home := t.TempDir()
	cxWriteCanonicalFixture(t, home, "a@example.test", true)
	cxWriteCanonicalFixture(t, home, "b@example.test", false)
	server := cxTestServer(t, true)
	server.cfg.CXCompatibility.SourceHome = home
	executor := &cxExecutionCaptureExecutor{response: coreexecutor.Response{Payload: []byte(`{"id":"resp-canonical","status":"completed","output":[]}`)}}
	server.handlers.AuthManager.RegisterExecutor(executor)
	var want []string
	for _, email := range []string{"a@example.test", "b@example.test", "a@example.test"} {
		cxWriteCanonicalFixture(t, home, email, true)
		account, err := cxcompat.NewStore(home).Account(email)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, helps.CXAccountAuth(home, account).ID)
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-6-luna","input":"hello","stream":false}`))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Session-Id", "unchanged-session")
		rr := httptest.NewRecorder()
		server.engine.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP %d: %s", rr.Code, rr.Body.String())
		}
		var upstream map[string]json.RawMessage
		if err := json.Unmarshal(executor.payload, &upstream); err != nil {
			t.Fatal(err)
		}
		if string(upstream["model"]) != `"gpt-6-luna"` {
			t.Fatalf("model changed: %s", executor.payload)
		}
	}
	if !reflect.DeepEqual(executor.authIDs, want) {
		t.Fatalf("executed %v, want %v", executor.authIDs, want)
	}
	if entries, err := os.ReadDir(server.cfg.AuthDir); err != nil || len(entries) != 0 {
		t.Fatalf("native auth store changed: %v, %v", entries, err)
	}
}

func TestCXCanonicalAccountsNeverEnterNativeSelection(t *testing.T) {
	home := t.TempDir()
	cxWriteCanonicalFixture(t, home, "a@example.test", true)
	server := cxTestServer(t, true)
	server.cfg.CXCompatibility.SourceHome = home
	executor := &cxExecutionCaptureExecutor{response: coreexecutor.Response{Payload: []byte(`{"status":"completed","output":[]}`)}}
	manager := server.handlers.AuthManager
	manager.RegisterExecutor(executor)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-6-luna","input":"hi","stream":false}`))
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("canonical request failed: %s", rr.Body.String())
	}
	canonicalID := executor.authIDs[0]
	// Even an explicitly registered model must not make a CX runtime record native-eligible.
	registry.GetGlobalRegistry().RegisterClient(canonicalID, "codex", []*registry.ModelInfo{{ID: "gpt-6-luna"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(canonicalID) })
	registerCXExecutionAccount(t, server, "native-only", "native@example.test")
	if err := os.Remove(filepath.Join(home, ".codex-accounts", "accounts", "a@example.test.json")); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		_, err := manager.Execute(context.Background(), []string{"codex"}, coreexecutor.Request{Model: "gpt-6-luna"}, coreexecutor.Options{})
		if err != nil {
			t.Fatal(err)
		}
	}
	want := []string{canonicalID, "native-only", "native-only", "native-only"}
	if !reflect.DeepEqual(executor.authIDs, want) {
		t.Fatalf("native selection leaked canonical account: %v", executor.authIDs)
	}
}

func TestCXCanonicalWarmingTargetsInactiveAccount(t *testing.T) {
	home := t.TempDir()
	cxWriteCanonicalFixture(t, home, "a@example.test", true)
	cxWriteCanonicalFixture(t, home, "b@example.test", false)
	activePath := filepath.Join(home, ".codex", "auth.json")
	before, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	server := cxTestServer(t, true)
	server.cfg.CXCompatibility.SourceHome = home
	executor := &cxExecutionCaptureExecutor{response: coreexecutor.Response{Payload: []byte(`{"status":"completed","output":[]}`)}}
	server.handlers.AuthManager.RegisterExecutor(executor)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(cxWarmBody))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(cxWarmHeader, "b@example.test")
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rr.Code, rr.Body.String())
	}
	account, err := cxcompat.NewStore(home).Account("b@example.test")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{helps.CXAccountAuth(home, account).ID}
	if !reflect.DeepEqual(executor.authIDs, want) {
		t.Fatalf("executed %v, want %v", executor.authIDs, want)
	}
	after, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("warming changed active selection")
	}
	if executor.headers.Get(cxWarmHeader) != "" {
		t.Fatal("targeting header reached executor")
	}
}
