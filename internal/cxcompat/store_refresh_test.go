package cxcompat

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestEnsureAuthSharesRefreshAndLeavesActiveAuthUntouched(t *testing.T) {
	home := t.TempDir()
	email := "shared@example.test"
	oldID := jwtWithClaims(map[string]any{"email": email})
	writeAccount(t, home, email, oauthAuth(jwtWithClaims(map[string]any{"exp": int64(1)}), "old-refresh", oldID))
	activePath := filepath.Join(home, ".codex", "auth.json")
	if err := os.MkdirAll(filepath.Dir(activePath), 0o700); err != nil {
		t.Fatal(err)
	}
	activeData := []byte(`{"auth_mode":"apikey","OPENAI_API_KEY":"sk-active"}`)
	if err := os.WriteFile(activePath, activeData, 0o600); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	exchange := func(context.Context, string) (string, string, string, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return jwtWithClaims(map[string]any{"exp": int64(4_000_000_000)}), "new-refresh", "new-id", nil
	}
	firstStore, secondStore := NewStoreWithExchange(home, exchange), NewStoreWithExchange(home, exchange)
	type outcome struct {
		auth AuthSnapshot
		err  error
	}
	results := make(chan outcome, 2)
	go func() {
		auth, err := firstStore.EnsureAuth(context.Background(), email, false, "")
		results <- outcome{auth, err}
	}()
	<-entered
	go func() {
		auth, err := secondStore.EnsureAuth(context.Background(), email, false, "")
		results <- outcome{auth, err}
	}()
	close(release)
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.auth.Tokens == nil || result.auth.Tokens.RefreshToken != "new-refresh" {
			t.Fatalf("auth = %#v", result.auth)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("exchange calls = %d; want 1", calls.Load())
	}
	gotActive, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotActive) != string(activeData) {
		t.Fatalf("active auth changed: %s", gotActive)
	}
}

func TestEnsureAuthAdoptsLatestTokenAfterExchange(t *testing.T) {
	home := t.TempDir()
	email := "winner@example.test"
	path := writeAccount(t, home, email, oauthAuth(jwtWithClaims(map[string]any{"exp": int64(1)}), "old-refresh", "old-id"))
	loginAuth := oauthAuth("login-access", "login-refresh", "login-id")
	store := NewStoreWithExchange(home, func(context.Context, string) (string, string, string, error) {
		if err := os.WriteFile(path, []byte(`{"email":"`+email+`","auth":`+loginAuth+`,"login_marker":"new"}`), 0o600); err != nil {
			return "", "", "", err
		}
		return "stale-access", "stale-refresh", "stale-id", nil
	})
	got, err := store.EnsureAuth(context.Background(), email, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tokens == nil || got.Tokens.AccessToken != "login-access" {
		t.Fatalf("winner = %#v", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record["login_marker"] != "new" {
		t.Fatal("concurrent login metadata lost")
	}
}

func TestEnsureAuthDoesNotResurrectRemovedAccount(t *testing.T) {
	home := t.TempDir()
	email := "removed@example.test"
	path := writeAccount(t, home, email, oauthAuth("expired", "refresh", "id"))
	store := NewStoreWithExchange(home, func(context.Context, string) (string, string, string, error) {
		if err := os.Remove(path); err != nil {
			return "", "", "", err
		}
		return "new-access", "new-refresh", "new-id", nil
	})
	if _, err := store.EnsureAuth(context.Background(), email, true, ""); err == nil {
		t.Fatal("refresh succeeded after account was removed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("removed account was recreated: stat error = %v", err)
	}
}

func TestAccountLockMetadataIsOwnerOnly(t *testing.T) {
	home := t.TempDir()
	email := "permissions@example.test"
	writeAccount(t, home, email, oauthAuth("access", "refresh", "id"))
	store := NewStore(home)
	if err := store.withAccountLock(context.Background(), email, func() error {
		lock := accountPath(store.accountsDir(), email) + ".lock"
		for path, want := range map[string]os.FileMode{lock: 0o700, filepath.Join(lock, "owner.json"): 0o600} {
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			if got := info.Mode().Perm(); got != want {
				return fmt.Errorf("mode %s = %o; want %o", filepath.Base(path), got, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFailedAccessTokenMismatchReturnsCurrentWinner(t *testing.T) {
	home := t.TempDir()
	email := "mismatch@example.test"
	writeAccount(t, home, email, oauthAuth("winner", "r", "id"))
	store := NewStoreWithExchange(home, func(context.Context, string) (string, string, string, error) {
		t.Fatal("unexpected exchange")
		return "", "", "", nil
	})
	got, err := store.EnsureAuth(context.Background(), email, true, "failed-old-token")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tokens == nil || got.Tokens.AccessToken != "winner" {
		t.Fatalf("auth = %#v", got)
	}
}

func TestRefreshPreservesUnknownFieldsAndUsesOwnerOnlyAtomicFile(t *testing.T) {
	home := t.TempDir()
	email := "preserve@example.test"
	path := writeAccount(t, home, email, `{"auth_mode":"chatgpt","tokens":{"access_token":"expired","refresh_token":"refresh","id_token":"id","account_id":"acct","extra_token":"keep"},"unknown_auth":{"v":7}}`)
	// Include unknown fields at each level to verify safe in-place credential replacement.
	fixture := []byte(`{"email":"` + email + `","addedAt":"fixed","extra_account":{"keep":true},"auth":{"auth_mode":"chatgpt","tokens":{"access_token":"expired","refresh_token":"refresh","id_token":"id","account_id":"acct","extra_token":"keep"},"unknown_auth":{"v":7}}}`)
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithExchange(home, func(context.Context, string) (string, string, string, error) {
		return jwtWithClaims(map[string]any{"exp": int64(4_000_000_000)}), "rotated", "new-id", nil
	})
	if _, err := store.EnsureAuth(context.Background(), email, true, ""); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	auth := value["auth"].(map[string]any)
	tokens := auth["tokens"].(map[string]any)
	if value["addedAt"] != "fixed" || value["extra_account"].(map[string]any)["keep"] != true || auth["unknown_auth"].(map[string]any)["v"] != float64(7) || tokens["extra_token"] != "keep" {
		t.Fatalf("unknown fields lost: %s", data)
	}
	if tokens["refresh_token"] != "rotated" || auth["last_refresh"] == nil {
		t.Fatalf("refresh fields missing: %s", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("account mode = %o", info.Mode().Perm())
	}
	for _, dir := range []string{filepath.Join(home, ".codex-accounts"), filepath.Dir(path)} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("directory mode %s = %o", dir, info.Mode().Perm())
		}
	}
}
