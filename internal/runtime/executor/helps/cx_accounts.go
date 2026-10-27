package helps

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/cxcompat"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const (
	CXStoreHomeAttribute    = "cx_store_home"
	CXAccountEmailAttribute = "cx_account_email"
	CXRuntimeOnlyAttribute  = "runtime_only"
)

type cxRefreshEvaluator struct{}

func (cxRefreshEvaluator) ShouldRefresh(time.Time, *cliproxyauth.Auth) bool { return false }

// CXAccountAuth materializes canonical CX account data as a runtime-only Codex auth.
func CXAccountAuth(home string, account cxcompat.AccountSnapshot) *cliproxyauth.Auth {
	email := strings.TrimSpace(account.Email)
	tokens := account.Auth.Tokens
	var access, refresh, id, accountID string
	if tokens != nil {
		access, refresh, id, accountID = tokens.AccessToken, tokens.RefreshToken, tokens.IDToken, tokens.AccountID
	}
	hash := sha256.Sum256([]byte(email))
	metadata := map[string]any{
		"type": "codex", "email": email, "access_token": access,
		"refresh_token": refresh, "id_token": id, "account_id": accountID,
		"expired": cxJWTExpiry(access), "last_refresh": account.Auth.LastRefresh,
	}
	return &cliproxyauth.Auth{
		ID: "cx-" + hex.EncodeToString(hash[:]), Provider: "codex",
		Attributes: map[string]string{
			"auth_kind": "oauth", CXRuntimeOnlyAttribute: "true", "request_plan_only": "true",
			CXStoreHomeAttribute: home, CXAccountEmailAttribute: email,
		},
		Metadata: metadata, Runtime: cxRefreshEvaluator{},
	}
}

func cxJWTExpiry(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	if decoder.Decode(&claims) != nil {
		return ""
	}
	seconds, err := claims.Exp.Int64()
	if err != nil || seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}
