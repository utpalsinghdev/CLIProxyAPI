package executor

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/cxcompat"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	cxStoreHomeAttribute    = helps.CXStoreHomeAttribute
	cxAccountEmailAttribute = helps.CXAccountEmailAttribute
	cxRuntimeOnlyAttribute  = helps.CXRuntimeOnlyAttribute
)

func isCXAccountAuth(auth *cliproxyauth.Auth) bool {
	if auth == nil || auth.Attributes == nil {
		return false
	}
	_, hasHome := auth.Attributes[cxStoreHomeAttribute]
	_, hasEmail := auth.Attributes[cxAccountEmailAttribute]
	return hasHome || hasEmail
}

func (e *CodexExecutor) ShouldPrepareRequestAuth(auth *cliproxyauth.Auth) bool {
	return isCXAccountAuth(auth)
}

func (e *CodexExecutor) PrepareRequestAuth(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if !e.ShouldPrepareRequestAuth(auth) {
		return auth, nil
	}
	prepared, err := e.prepareCXAccountAuth(ctx, auth, false)
	if err != nil {
		return nil, cxAuthUnauthorized(err)
	}
	return prepared, nil
}

func (e *CodexExecutor) prepareCXAccountAuth(ctx context.Context, auth *cliproxyauth.Auth, force bool) (*cliproxyauth.Auth, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if auth == nil || auth.Attributes == nil || auth.Attributes[cxRuntimeOnlyAttribute] != "true" {
		return nil, errors.New("invalid CX auth marker")
	}
	home := strings.TrimSpace(auth.Attributes[cxStoreHomeAttribute])
	email := strings.TrimSpace(auth.Attributes[cxAccountEmailAttribute])
	if !filepath.IsAbs(home) || email == "" || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return nil, errors.New("invalid CX auth identity")
	}

	store := cxcompat.NewStore(home)
	if provider, ok := auth.Runtime.(interface{ CXCompatStore() *cxcompat.Store }); ok && provider.CXCompatStore() != nil {
		store = provider.CXCompatStore()
	}
	account, err := store.Account(email)
	if err != nil || account.Email != email {
		return nil, errors.New("CX account is unavailable")
	}
	failedToken := ""
	if force {
		failedToken = cxMetadataString(auth, "access_token")
	}
	credentials, err := store.EnsureAuth(ctx, email, force, failedToken)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || credentials.Tokens == nil {
		return nil, errors.New("CX account credentials are unavailable")
	}

	updated := auth.Clone()
	canonical := helps.CXAccountAuth(home, cxcompat.AccountSnapshot{Email: email, Auth: credentials})
	if updated.Metadata == nil {
		updated.Metadata = make(map[string]any)
	}
	for _, key := range []string{"type", "email", "access_token", "refresh_token", "id_token", "account_id", "expired", "last_refresh"} {
		updated.Metadata[key] = canonical.Metadata[key]
	}
	return updated, nil
}

func preserveCXResponsesInput(body, source []byte) []byte {
	input := gjson.GetBytes(source, "input")
	if !input.IsArray() {
		return body
	}
	body, _ = sjson.SetRawBytes(body, "input", []byte(input.Raw))
	for index, item := range input.Array() {
		if item.Get("role").String() == "system" {
			body, _ = sjson.SetBytes(body, "input."+strconv.Itoa(index)+".role", "developer")
		}
	}
	return body
}

func cxMetadataString(auth *cliproxyauth.Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, _ := auth.Metadata[key].(string)
	return value
}

func cxAuthUnauthorized(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return statusErr{code: http.StatusUnauthorized, msg: "codex executor: CX credentials are unavailable"}
}

func (e *CodexAutoExecutor) ShouldPrepareRequestAuth(auth *cliproxyauth.Auth) bool {
	return e != nil && e.httpExec != nil && e.httpExec.ShouldPrepareRequestAuth(auth)
}

func (e *CodexAutoExecutor) PrepareRequestAuth(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if e == nil || e.httpExec == nil {
		return nil, statusErr{code: http.StatusUnauthorized, msg: "codex executor: CX credentials are unavailable"}
	}
	return e.httpExec.PrepareRequestAuth(ctx, auth)
}
