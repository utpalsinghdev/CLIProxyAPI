package helps

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/cxcompat"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestCXAccountAuthMaterializesStableRuntimeAuth(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	token := "header." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp))) + ".signature"
	account := cxcompat.AccountSnapshot{Email: "person@example.com", Auth: cxcompat.AuthSnapshot{
		LastRefresh: "2026-01-02T03:04:05Z",
		Tokens:      &cxcompat.TokenSet{AccessToken: token, RefreshToken: "refresh", IDToken: "id", AccountID: "acct"},
	}}
	first := CXAccountAuth("/explicit/home", account)
	second := CXAccountAuth("/explicit/home", account)
	if first.ID != second.ID {
		t.Fatalf("unstable ID: %q != %q", first.ID, second.ID)
	}
	if first.ID[:3] != "cx-" || first.Provider != "codex" {
		t.Fatalf("identity = (%q, %q), want cx-prefixed Codex auth", first.ID, first.Provider)
	}
	for key, want := range map[string]string{
		"auth_kind": "oauth", CXRuntimeOnlyAttribute: "true", CXStoreHomeAttribute: "/explicit/home", CXAccountEmailAttribute: "person@example.com",
	} {
		if got := first.Attributes[key]; got != want {
			t.Errorf("attribute %q = %q, want %q", key, got, want)
		}
	}
	for key, want := range map[string]any{"type": "codex", "email": account.Email, "access_token": token, "refresh_token": "refresh", "id_token": "id", "account_id": "acct", "last_refresh": account.Auth.LastRefresh} {
		if got := first.Metadata[key]; got != want {
			t.Errorf("metadata %q = %v, want %v", key, got, want)
		}
	}
	if got, want := first.Metadata["expired"], time.Unix(exp, 0).UTC().Format(time.RFC3339); got != want {
		t.Errorf("expired = %v, want %q", got, want)
	}
	evaluator, ok := first.Runtime.(cliproxyauth.RefreshEvaluator)
	if !ok || evaluator.ShouldRefresh(time.Now(), first) {
		t.Fatal("canonical CX auth must disable background refresh")
	}
	first.Metadata["access_token"] = "mutated"
	if account.Auth.Tokens.AccessToken != token {
		t.Fatal("materialization mutated canonical snapshot")
	}
}
