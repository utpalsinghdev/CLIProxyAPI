package cxcompat

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func jwtWithClaims(claims map[string]any) string {
	payload, _ := json.Marshal(claims)
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func writeAccount(t *testing.T, home, email string, auth string) string {
	t.Helper()
	dir := filepath.Join(home, ".codex-accounts", "accounts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := accountPath(dir, email)
	data := []byte(`{"email":` + quote(email) + `,"addedAt":"now","auth":` + auth + `}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func quote(value string) string { encoded, _ := json.Marshal(value); return string(encoded) }

func oauthAuth(access, refresh, id string) string {
	return `{"tokens":{"access_token":` + quote(access) + `,"refresh_token":` + quote(refresh) + `,"id_token":` + quote(id) + `}}`
}

func TestActiveAccountRereadsIdentityEachRequest(t *testing.T) {
	home := t.TempDir()
	first, second := "a@example.test", "b@example.test"
	writeAccount(t, home, first, oauthAuth("a", "ra", jwtWithClaims(map[string]any{"email": first})))
	writeAccount(t, home, second, oauthAuth("b", "rb", jwtWithClaims(map[string]any{"email": second})))
	store := NewStore(home)
	writeActive := func(email string) {
		t.Helper()
		path := filepath.Join(home, ".codex", "auth.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(oauthAuth("active", "active-refresh", jwtWithClaims(map[string]any{"https://api.openai.com/profile": map[string]any{"email": email}}))), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, email := range []string{first, second, first} {
		writeActive(email)
		active, err := store.ActiveAccount()
		if err != nil {
			t.Fatal(err)
		}
		if active == nil || active.Email != email {
			t.Fatalf("active = %#v; want %q", active, email)
		}
	}
}

func TestListOAuthAccountsSortsAndExcludesAPIKeys(t *testing.T) {
	home := t.TempDir()
	id := jwtWithClaims(map[string]any{"email": "x"})
	writeAccount(t, home, "z@example.test", oauthAuth("z", "rz", id))
	writeAccount(t, home, "A@example.test", oauthAuth("A", "rA", id))
	writeAccount(t, home, "a@example.test", oauthAuth("a", "ra", id))
	writeAccount(t, home, "key@example.test", `{"auth_mode":"apikey","OPENAI_API_KEY":"sk-test"}`)
	accounts, err := NewStore(home).ListOAuthAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 3 || accounts[0].Email != "a@example.test" || accounts[1].Email != "A@example.test" || accounts[2].Email != "z@example.test" {
		t.Fatalf("account order = %#v", accounts)
	}
}

func TestAccountIdentityAndSanitizationPreventTraversal(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(home, "outside.json")
	if err := os.WriteFile(outside, []byte(`{"email":"../outside"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(home)
	if _, err := store.Account("../outside"); err == nil {
		t.Fatal("expected exact-identity lookup failure")
	}
	if _, err := store.EnsureAuth(context.Background(), "../../outside", true, ""); err == nil {
		t.Fatal("expected invalid account lookup failure")
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"email":"../outside"}` {
		t.Fatalf("outside file changed: %s", data)
	}
}

func TestUnknownLockIsNotReclaimedAndWaitIsCancellable(t *testing.T) {
	home := t.TempDir()
	email := "lock@example.test"
	writeAccount(t, home, email, oauthAuth("expired", "refresh", "id"))
	lock := accountPath(filepath.Join(home, ".codex-accounts", "accounts"), email) + ".lock"
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewStoreWithExchange(home, func(context.Context, string) (string, string, string, error) {
		t.Fatal("exchange called")
		return "", "", "", nil
	}).EnsureAuth(ctx, email, true, "")
	if err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("error = %v", err)
	}
	if _, statErr := os.Stat(lock); statErr != nil {
		t.Fatalf("unknown lock was removed: %v", statErr)
	}
}

func TestCancelledRefreshDoesNotAcquireFreeLockOrExchange(t *testing.T) {
	home := t.TempDir()
	email := "cancelled@example.test"
	writeAccount(t, home, email, oauthAuth("expired", "refresh", "id"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := NewStoreWithExchange(home, func(context.Context, string) (string, string, string, error) {
		t.Fatal("cancelled refresh called token exchange")
		return "", "", "", nil
	})
	if _, err := store.EnsureAuth(ctx, email, true, ""); err == nil {
		t.Fatal("cancelled refresh succeeded")
	}
	lock := accountPath(filepath.Join(home, ".codex-accounts", "accounts"), email) + ".lock"
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatalf("cancelled refresh left lock: %v", err)
	}
}

func TestExpiredUsesCXGrace(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	for _, tt := range []struct {
		exp  int64
		want bool
	}{{now.Unix() + 59, true}, {now.Unix() + 60, false}, {now.Unix() - 1, true}} {
		token := jwtWithClaims(map[string]any{"exp": tt.exp})
		if got := expired(token, now); got != tt.want {
			t.Errorf("exp %d: got %v want %v", tt.exp, got, tt.want)
		}
	}
	if expired("malformed", now) {
		t.Fatal("malformed token should match CX's non-expired fallback")
	}
}
