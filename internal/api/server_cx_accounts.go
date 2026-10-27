package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/cxcompat"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// cxAccountBridge serializes runtime reconciliation, not inference. Credentials are
// frozen in each request plan; the canonical CX store owns all token writes.
type cxAccountBridge struct {
	mu sync.Mutex
}

func (s *Server) cxCanonicalAccounts(c *gin.Context, target string) (bool, bool) {
	home := strings.TrimSpace(s.cfg.CXCompatibility.SourceHome)
	if home == "" {
		return false, true
	}
	if !filepath.IsAbs(home) || s.cfg.Home.Enabled || s.handlers == nil || s.handlers.AuthManager == nil {
		cxError(c, http.StatusServiceUnavailable, "cx_store_unavailable", "CX account source is unavailable")
		return false, false
	}
	if target == "" && s.pluginHost != nil && s.pluginHost.HasModelRouters() {
		return false, true
	}
	body, err := cxcompat.ReadRequest(c.Writer, c.Request)
	if err != nil {
		cxRequestError(c, err)
		return false, false
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body.Raw))
	var model string
	if json.Unmarshal(body.Fields["model"], &model) != nil || strings.TrimSpace(model) == "" {
		cxError(c, http.StatusBadRequest, "invalid_request", "A model string and input string or array are required")
		return false, false
	}
	if target == "" {
		for _, provider := range util.GetProviderName(thinking.ParseSuffix(model).ModelName) {
			if provider != "codex" {
				return false, true
			}
		}
	}
	store := cxcompat.NewStore(home)
	accounts, err := store.ListOAuthAccounts()
	if err != nil {
		cxError(c, http.StatusServiceUnavailable, "cx_store_unavailable", "CX account source is unavailable")
		return false, false
	}
	active, err := store.ActiveAccount()
	if err != nil {
		cxError(c, http.StatusServiceUnavailable, "cx_store_unavailable", "CX active account is unavailable")
		return false, false
	}
	ordered := make([]cxcompat.AccountSnapshot, 0, len(accounts))
	if target != "" {
		for _, account := range accounts {
			if account.Email == target {
				ordered = append(ordered, account)
			}
		}
		if len(ordered) != 1 {
			cxError(c, http.StatusNotFound, "target_not_found", "Stored warming account is unavailable")
			return false, false
		}
	} else {
		if active != nil {
			for _, account := range accounts {
				if account.Email == active.Email {
					ordered = append(ordered, account)
					break
				}
			}
		}
		for _, account := range accounts {
			if active == nil || account.Email != active.Email {
				ordered = append(ordered, account)
			}
		}
	}
	if len(ordered) == 0 {
		cxError(c, http.StatusUnauthorized, "auth_unavailable", "No stored OAuth account can authenticate")
		return false, false
	}
	s.cxAccounts.mu.Lock()
	if _, exists := s.handlers.AuthManager.Executor("codex"); !exists {
		s.handlers.AuthManager.RegisterExecutor(executor.NewCodexAutoExecutor(s.cfg))
	}
	s.cxAccounts.mu.Unlock()
	auths, err := s.cxAccounts.reconcile(s.handlers.AuthManager, home, ordered)
	if err != nil {
		cxError(c, http.StatusServiceUnavailable, "cx_store_unavailable", "CX runtime accounts could not be prepared")
		return false, false
	}
	plan := coreauth.RequestAuthPlan{Auths: auths, Model: model}
	if target == "" {
		plan.AllowFallback = cxcompat.AllowFallback
	}
	ctx := coreauth.WithRequestAuthPlan(c.Request.Context(), plan)
	c.Request = c.Request.WithContext(ctx)
	return true, true
}

func (b *cxAccountBridge) reconcile(manager *coreauth.Manager, home string, accounts []cxcompat.AccountSnapshot) ([]*coreauth.Auth, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	auths := make([]*coreauth.Auth, 0, len(accounts))
	for _, account := range accounts {
		auth := helps.CXAccountAuth(home, account)
		if existing, ok := manager.GetByID(auth.ID); ok {
			// Keep counters and cooldown generations. Request plans still carry their
			// own credential snapshot, not a mutable reference to this runtime record.
			if existing.Attributes[helps.CXStoreHomeAttribute] != home {
				return nil, errors.New("CX account source conflicts with an existing runtime identity")
			}
			auth.RegistrationEpoch = existing.RegistrationEpoch
			auth.Generation = existing.Generation
		} else {
			registered, err := manager.Register(coreauth.WithSkipPersist(nil), auth.Clone())
			if err != nil || registered == nil {
				return nil, errors.New("CX runtime account registration failed")
			}
			auth.RegistrationEpoch = registered.RegistrationEpoch
			auth.Generation = registered.Generation
		}
		auths = append(auths, auth)
	}
	return auths, nil
}
