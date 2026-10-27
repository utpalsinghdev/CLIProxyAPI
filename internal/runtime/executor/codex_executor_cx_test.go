package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/cxcompat"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type cxTestStoreProvider struct{ store *cxcompat.Store }

func (p cxTestStoreProvider) CXCompatStore() *cxcompat.Store { return p.store }

func TestCodexCXPrepareRefreshesExpiredAuthWithoutMutatingSnapshot(t *testing.T) {
	home := t.TempDir()
	oldToken := cxTestJWT(time.Now().Add(-time.Minute))
	newToken := cxTestJWT(time.Now().Add(time.Hour))
	writeCXTestAccount(t, home, "account@example.com", oldToken, "old-refresh", "old-id", "old-acct", "2020-01-01T00:00:00Z")
	activePath := filepath.Join(home, ".codex", "auth.json")
	if err := os.MkdirAll(filepath.Dir(activePath), 0o700); err != nil {
		t.Fatal(err)
	}
	activeBytes := []byte(`{"sentinel":"must remain untouched"}`)
	if err := os.WriteFile(activePath, activeBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	var exchanges int
	store := cxcompat.NewStoreWithExchange(home, func(context.Context, string) (string, string, string, error) {
		exchanges++
		return newToken, "new-refresh", "new-id", nil
	})
	auth := helps.CXAccountAuth(home, cxcompat.AccountSnapshot{Email: "account@example.com", Auth: cxcompat.AuthSnapshot{
		Tokens: &cxcompat.TokenSet{AccessToken: oldToken, RefreshToken: "old-refresh", IDToken: "old-id", AccountID: "old-acct"},
	}})
	auth.Runtime = cxTestStoreProvider{store}

	auto := NewCodexAutoExecutor(nil)
	if !auto.ShouldPrepareRequestAuth(auth) {
		t.Fatal("CodexAutoExecutor.ShouldPrepareRequestAuth() = false for CX auth")
	}
	prepared, err := auto.PrepareRequestAuth(context.Background(), auth)
	if err != nil {
		t.Fatalf("PrepareRequestAuth() error = %v", err)
	}
	if exchanges != 1 || prepared.Metadata["access_token"] != newToken || prepared.Metadata["refresh_token"] != "new-refresh" {
		t.Fatalf("prepared credentials = %#v, exchange count %d", prepared.Metadata, exchanges)
	}
	if auth.Metadata["access_token"] != oldToken || auth.Metadata["refresh_token"] != "old-refresh" {
		t.Fatal("preparation mutated input auth snapshot")
	}
	updated, err := store.Account("account@example.com")
	if err != nil || updated.Auth.Tokens.AccessToken != newToken {
		t.Fatalf("canonical store not refreshed: account=%#v err=%v", updated, err)
	}
	gotActive, err := os.ReadFile(activePath)
	if err != nil || string(gotActive) != string(activeBytes) {
		t.Fatalf("active auth file changed: %q, err=%v", gotActive, err)
	}
}

func TestCodexCXRefreshAdoptsConcurrentStoredWinner(t *testing.T) {
	home := t.TempDir()
	winner := cxTestJWT(time.Now().Add(time.Hour))
	writeCXTestAccount(t, home, "account@example.com", winner, "winner-refresh", "winner-id", "winner-acct", "2026-01-01T00:00:00Z")
	var exchanges int
	store := cxcompat.NewStoreWithExchange(home, func(context.Context, string) (string, string, string, error) {
		exchanges++
		return "unexpected", "unexpected", "unexpected", nil
	})
	failed := helps.CXAccountAuth(home, cxcompat.AccountSnapshot{Email: "account@example.com", Auth: cxcompat.AuthSnapshot{
		Tokens: &cxcompat.TokenSet{AccessToken: "failed-token", RefreshToken: "stale-refresh", IDToken: "stale-id", AccountID: "stale-account"},
	}})
	failed.Runtime = cxTestStoreProvider{store}
	failed.Attributes["custom"] = "retained"
	failed.Metadata["other"] = "retained"

	updated, err := NewCodexExecutor(nil).Refresh(context.Background(), failed)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if exchanges != 0 || updated.Metadata["access_token"] != winner || updated.Metadata["refresh_token"] != "winner-refresh" {
		t.Fatalf("updated credentials = %#v, exchange count %d", updated.Metadata, exchanges)
	}
	if failed.Metadata["access_token"] != "failed-token" {
		t.Fatal("Refresh mutated attempted auth")
	}
	if updated.ID != failed.ID || updated.Attributes["custom"] != "retained" || updated.Metadata["other"] != "retained" {
		t.Fatal("Refresh did not preserve auth identity and unrelated fields")
	}
}

func TestCodexCXPreparationRejectsUnknownOrMismatchedSource(t *testing.T) {
	for _, tc := range []struct {
		name  string
		email string
	}{
		{name: "unknown", email: "missing@example.com"},
		{name: "mismatched", email: "other@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			writeCXTestAccount(t, home, "account@example.com", cxTestJWT(time.Now().Add(time.Hour)), "refresh", "id", "account", "")
			auth := helps.CXAccountAuth(home, cxcompat.AccountSnapshot{Email: tc.email})
			if !NewCodexExecutor(nil).ShouldPrepareRequestAuth(auth) {
				t.Fatal("ShouldPrepareRequestAuth() = false for marked CX auth")
			}
			_, err := NewCodexExecutor(nil).PrepareRequestAuth(context.Background(), auth)
			var status interface{ StatusCode() int }
			if !errors.As(err, &status) || status.StatusCode() != http.StatusUnauthorized {
				t.Fatalf("PrepareRequestAuth() error = %v, want typed 401", err)
			}
			if err.Error() != "codex executor: CX credentials are unavailable" {
				t.Fatalf("error is not sanitized: %q", err)
			}
		})
	}
}

func TestCodexCXFailClosedAndNativeAuthUnchanged(t *testing.T) {
	executor := NewCodexExecutor(nil)
	for _, auth := range []*cliproxyauth.Auth{
		{Provider: "codex", Attributes: map[string]string{helps.CXRuntimeOnlyAttribute: "true", helps.CXAccountEmailAttribute: "a@example.com"}},
		{Provider: "codex", Attributes: map[string]string{helps.CXRuntimeOnlyAttribute: "false", helps.CXStoreHomeAttribute: t.TempDir(), helps.CXAccountEmailAttribute: "a@example.com"}},
	} {
		if _, err := executor.PrepareRequestAuth(context.Background(), auth); err == nil {
			t.Fatal("malformed marked CX auth prepared without error")
		}
	}

	native := &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"access_token": "native-token"}}
	if executor.ShouldPrepareRequestAuth(native) {
		t.Fatal("ordinary native auth requested preparation")
	}
	prepared, err := executor.PrepareRequestAuth(context.Background(), native)
	if err != nil || prepared != native {
		t.Fatalf("ordinary native preparation = (%p, %v), want original auth and nil", prepared, err)
	}
	refreshed, err := executor.Refresh(context.Background(), native)
	if err != nil || refreshed != native || native.Metadata["access_token"] != "native-token" {
		t.Fatalf("ordinary native Refresh changed: refreshed=%p err=%v metadata=%v", refreshed, err, native.Metadata)
	}
}

func TestCodexCXCancelledAcquisitionPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	auth := helps.CXAccountAuth(t.TempDir(), cxcompat.AccountSnapshot{Email: "cancel@example.test"})
	_, err := NewCodexExecutor(nil).PrepareRequestAuth(ctx, auth)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	_, err = NewCodexExecutor(nil).Refresh(ctx, auth)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh lost context cancellation: %v", err)
	}
}

func cxTestJWT(exp time.Time) string {
	payload, _ := json.Marshal(map[string]int64{"exp": exp.Unix()})
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func writeCXTestAccount(t *testing.T, home, email, access, refresh, id, accountID, lastRefresh string) {
	t.Helper()
	path := filepath.Join(home, ".codex-accounts", "accounts", email+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	record := map[string]any{
		"email": email,
		"auth": map[string]any{"auth_mode": "oauth", "OPENAI_API_KEY": "", "last_refresh": lastRefresh,
			"tokens": map[string]string{"access_token": access, "refresh_token": refresh, "id_token": id, "account_id": accountID}},
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(fmt.Errorf("write CX test account: %w", err))
	}
}
